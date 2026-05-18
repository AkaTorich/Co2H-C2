// Private heap with encrypted-at-rest "masked" allocations. During sleep we
// walk this heap and XOR the contents with a random mask; see
// opsec/sleepmask_ekko.c.
#include "beacon.h"

static HANDLE g_heap = NULL;

static void ensure_heap(void) {
    if (!g_heap) g_heap = HeapCreate(0, 0, 0);
}

void* bmalloc(size_t n) {
    ensure_heap();
    return HeapAlloc(g_heap, 0, n);
}

void* bcalloc(size_t n) {
    ensure_heap();
    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, n);
}

void bfree(void* p) {
    if (p && g_heap) HeapFree(g_heap, 0, p);
}

void* brealloc(void* p, size_t n) {
    ensure_heap();
    if (!p) return bmalloc(n);
    return HeapReAlloc(g_heap, 0, p, n);
}
