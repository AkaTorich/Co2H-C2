// Common header shared between generator and loader stub.
// Defines the in-memory layout the stub expects to find right after itself.
#ifndef SCELOT_INSTANCE_H
#define SCELOT_INSTANCE_H

#include <stdint.h>

#define SCELOT_MAGIC 0x53434C54u // 'SCLT'

// Payload categories the loader knows how to dispatch.
enum {
    SCELOT_PAYLOAD_PE_EXE   = 1,
    SCELOT_PAYLOAD_PE_DLL   = 2,
    SCELOT_PAYLOAD_NET_EXE  = 3,
    SCELOT_PAYLOAD_NET_DLL  = 4
};

// Architecture of the payload (must match the architecture of the stub itself).
enum {
    SCELOT_ARCH_X86 = 1,
    SCELOT_ARCH_X64 = 2
};

// What to do once the payload finishes running.
enum {
    SCELOT_EXIT_PROCESS = 1,
    SCELOT_EXIT_THREAD  = 2,
    SCELOT_EXIT_RETURN  = 3
};

#pragma pack(push, 1)
typedef struct _SCELOT_INSTANCE {
    uint32_t magic;          // SCELOT_MAGIC, sanity check after decryption
    uint32_t instance_size;  // size of this struct in bytes
    uint32_t payload_size;   // size of the encrypted PE/.NET image right after this struct
    uint32_t payload_type;   // one of SCELOT_PAYLOAD_*
    uint32_t arch;           // SCELOT_ARCH_*
    uint32_t exit_mode;      // SCELOT_EXIT_*
    uint8_t  payload_iv[16]; // IV for the payload AES-CTR stream
    char     export_name[64];// for DLL payloads, name of the exported function to call
    char     net_class[128]; // for .NET payloads, "Namespace.Class"
    char     net_method[64]; // for .NET payloads, method name
    char     args[512];      // command-line arguments (UTF-8) injected via GetCommandLine* hook
} SCELOT_INSTANCE;
#pragma pack(pop)

#endif // SCELOT_INSTANCE_H
