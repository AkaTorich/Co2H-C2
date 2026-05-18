// Extracts the .text section into a flat blob laid out so that runtime
// addresses match link-time addresses relative to __ImageBase.
//
// Blob layout:
//   offset 0..4         : JMP rel32 to _scelot_entry inside .text
//   offset 5..(textVA-1): zero padding (replaces PE headers)
//   offset textVA..end  : raw .text bytes
//
// Result: when the blob is loaded at runtime address P, byte P+textVA+i
// equals link-time .text byte i. Critically, MSVC's "__ImageBase + offset"
// addressing pattern (which the compiler emits for clusters of static
// volatile data) computes target = P + offset at runtime, which lands on
// the correct byte inside the blob.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static void* slurp(const char* path, DWORD* out_size) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    void* buf = HeapAlloc(GetProcessHeap(), 0, sz);
    DWORD rd;
    ReadFile(h, buf, sz, &rd, NULL);
    CloseHandle(h);
    *out_size = sz;
    return buf;
}

int main(int argc, char** argv) {
    if (argc != 3) { fputs("usage: extract_text <in.exe> <out.bin>\n", stderr); return 1; }
    DWORD sz;
    uint8_t* buf = slurp(argv[1], &sz);
    if (!buf) { fputs("read failed\n", stderr); return 2; }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Name[0] == '.' && sec->Name[1] == 't' && sec->Name[2] == 'e' &&
            sec->Name[3] == 'x' && sec->Name[4] == 't') {
            DWORD text_va = sec->VirtualAddress;       // typically 0x1000
            DWORD text_size = sec->SizeOfRawData;
            // entry must live inside .text
            if (entry_rva < text_va || entry_rva >= text_va + text_size) {
                fputs("entry point not in .text\n", stderr);
                return 4;
            }
            DWORD blob_size = text_va + text_size;     // .text VA + .text size
            uint8_t* out = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blob_size);

            // JMP rel32 at blob offset 0 to entry_rva.
            // Encoding: E9 <rel32>; rel32 = target - next_rip = entry_rva - 5.
            uint32_t rel32 = entry_rva - 5;
            out[0] = 0xE9;
            out[1] = (uint8_t)(rel32       & 0xFF);
            out[2] = (uint8_t)((rel32 >> 8) & 0xFF);
            out[3] = (uint8_t)((rel32 >> 16)& 0xFF);
            out[4] = (uint8_t)((rel32 >> 24)& 0xFF);
            // bytes [5..text_va) remain zero (HEAP_ZERO_MEMORY).
            // .text content at offset text_va.
            for (DWORD k = 0; k < text_size; ++k) {
                out[text_va + k] = buf[sec->PointerToRawData + k];
            }

            HANDLE o = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, 0, NULL);
            DWORD wr;
            WriteFile(o, out, blob_size, &wr, NULL);
            CloseHandle(o);
            printf("extracted %u bytes total (text_va=0x%x text_size=%u entry_rva=0x%x)\n",
                   blob_size, text_va, text_size, entry_rva);
            return 0;
        }
    }
    fputs(".text not found\n", stderr);
    return 3;
}
