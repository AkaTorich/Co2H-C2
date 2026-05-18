// Memory allocator wrappers for the Linux beacon.
// Uses standard malloc/free — acceptable on Linux (unlike Windows beacon which avoids CRT).

#include "beacon.h"
#include <stdlib.h>
#include <string.h>

void* bmalloc(size_t n) {
    if (!n) return NULL;
    return malloc(n);
}

void* bcalloc(size_t n) {
    if (!n) return NULL;
    return calloc(1, n);
}

void bfree(void* p) {
    if (p) free(p);
}

void* brealloc(void* p, size_t n) {
    if (!n) { bfree(p); return NULL; }
    return realloc(p, n);
}
