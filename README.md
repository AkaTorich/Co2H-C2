# Co2H

A modular C2 framework for authorized red team and penetration testing operations.

## Components

| Directory | Description |
|-----------|-------------|
| `server/` | Teamserver (Asio + OpenSSL, cross-platform) |
| `client/` | Operator GUI client (Qt 6, cross-platform) |
| `beacon/` | Windows implant x64/x86 (MSVC, WinAPI, no CRT) |
| `beacon-linux/` | Linux implant x64 (OpenSSL, static) |
| `tools/artifact-gen/` | Artifact generator (EXE/DLL/raw shellcode) |
| `kit/` | Artifact Kit, Sleep Mask Kit, Process Inject Kit |
| `common/` | Shared protocol and crypto library |
| `profiles/` | Malleable C2 profiles |
| `plugins/` | Client-side plugins |
| `sdk/` | Client-side plugins SDK |
| `bof/` | Beacon Object Files |
| `docs/` | Operator manual (CHM) |

## Building

### Prerequisites

- CMake >= 3.24
- **Windows**: Visual Studio 2022 Build Tools (MSVC v143), Qt 6.5+
- **Linux**: GCC 11+ or Clang 14+, OpenSSL 3.x, Qt 6.5+
- Header-only deps (included in `thirdparty/`): Asio, toml++, spdlog, msgpack-c, sol2, zstd

### Build (Windows)

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Build (Linux)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)
```

## Features

- HTTPS/TCP/SMB/DNS listeners with malleable traffic profiles
- Reflective DLL injection, module stomping, NTDLL unhooking, early bird APC, direct syscalls
- Sleep mask encryption (Ekko timer, Foliage APC, ChaCha20, stack spoofing)
- Beacon Object File (BOF) loader
- Artifact Kit with 6 execution methods and API hash resolution (ROR13)
- SysWhispers4 integration with automatic patching pipeline
- Lua scripting engine for automation
- Multi-operator support with mTLS authentication
- Fallback C2 channels

## Disclaimer

This software is intended for authorized security testing and research only. Users are responsible for complying with all applicable laws. The authors assume no liability for misuse.

## License

[BSD-3-Clause](LICENSE)

Third-party licenses: [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES)
