// PE inspection helpers used by the generator.
#ifndef SCELOT_PE_PARSER_H
#define SCELOT_PE_PARSER_H

#include <stdint.h>

typedef struct _PE_INFO {
    int     arch;        // SCELOT_ARCH_X86 / X64
    int     is_dll;
    int     is_dotnet;
} PE_INFO;

int pe_inspect(const uint8_t* image, uint32_t size, PE_INFO* out);

#endif
