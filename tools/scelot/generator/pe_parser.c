// Minimal PE inspector: detect architecture, DLL flag, .NET via the
// COM descriptor data directory.
#include "pe_parser.h"
#include "instance.h"

#include <windows.h>

int pe_inspect(const uint8_t* image, uint32_t size, PE_INFO* out) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return -1;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -2;
    if ((uint32_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > size) return -3;
    const IMAGE_NT_HEADERS32* nt32 = (const IMAGE_NT_HEADERS32*)(image + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return -4;

    out->is_dll = (nt32->FileHeader.Characteristics & IMAGE_FILE_DLL) ? 1 : 0;
    out->is_dotnet = 0;

    if (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        out->arch = SCELOT_ARCH_X64;
        const IMAGE_NT_HEADERS64* nt64 = (const IMAGE_NT_HEADERS64*)nt32;
        const IMAGE_DATA_DIRECTORY* d =
            &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (d->Size && d->VirtualAddress) out->is_dotnet = 1;
    } else if (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        out->arch = SCELOT_ARCH_X86;
        const IMAGE_DATA_DIRECTORY* d =
            &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (d->Size && d->VirtualAddress) out->is_dotnet = 1;
    } else {
        return -5;
    }
    return 0;
}
