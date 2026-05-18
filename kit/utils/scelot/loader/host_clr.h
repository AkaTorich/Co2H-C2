// In-memory .NET assembly hosting via the legacy ICorRuntimeHost path.
#ifndef SCELOT_HOST_CLR_H
#define SCELOT_HOST_CLR_H

#include <stdint.h>
#include <windows.h>
#include "instance.h"

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);

int host_clr_run(fn_LoadLibraryA pLL, fn_GetProcAddress pGPA,
                 const uint8_t* assembly, uint32_t size,
                 const SCELOT_INSTANCE* inst);

#endif
