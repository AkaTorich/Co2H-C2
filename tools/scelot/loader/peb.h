// PEB walking and API resolution by hash. No CRT, no imports.
#ifndef SCELOT_PEB_H
#define SCELOT_PEB_H

#include <stdint.h>

void* peb_find_module(uint32_t name_hash);                   // returns HMODULE
void* peb_find_proc(void* module, uint32_t proc_hash);       // returns FARPROC

#endif
