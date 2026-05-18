cmake_minimum_required(VERSION 3.20)
project(scelot_payloads C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY                "${CMAKE_BINARY_DIR}/out")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_BINARY_DIR}/out")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY                "${CMAKE_BINARY_DIR}/out")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_BINARY_DIR}/out")

# All native payloads built without CRT so their entry point is called
# directly by the loader (no CRT startup that bypasses the IAT hooks).
set(NOCRT_C_FLAGS /Zl /GS- /GR- /EHs-c-)
set(NOCRT_LINK_FLAGS /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ENTRY:scelot_entry)

# 1. MessageBoxA payload.
add_executable(hello_msg payloads/hello_msg/hello_msg.c)
target_compile_options(hello_msg PRIVATE ${NOCRT_C_FLAGS})
target_link_options(hello_msg PRIVATE ${NOCRT_LINK_FLAGS})
target_link_libraries(hello_msg PRIVATE user32 kernel32)

# 2. Console payload printing GetCommandLineA via WriteFile.
add_executable(args_echo payloads/args_echo/args_echo.c)
target_compile_options(args_echo PRIVATE ${NOCRT_C_FLAGS})
# Console subsystem so the parent cmd inherits stdout.
target_link_options(args_echo PRIVATE /NODEFAULTLIB /SUBSYSTEM:CONSOLE /ENTRY:scelot_entry)
target_link_libraries(args_echo PRIVATE kernel32)

# 3. DLL with Run(LPSTR) export.
add_library(dll_run SHARED payloads/dll_run/dll_run.c)
target_compile_options(dll_run PRIVATE ${NOCRT_C_FLAGS})
target_link_options(dll_run PRIVATE /NODEFAULTLIB /ENTRY:_DllMainCRTStartup)
target_link_libraries(dll_run PRIVATE user32 kernel32)
set_target_properties(dll_run PROPERTIES PREFIX "" OUTPUT_NAME "dll_run")

# Universal launcher.
file(WRITE "${CMAKE_BINARY_DIR}/launcher.c"
"#include <windows.h>\n"
"#include <stdio.h>\n"
"typedef void (*fn)(void);\n"
"int main(int argc, char** argv) {\n"
"  if (argc < 2) { puts(\"usage: launcher <bin>\"); return 1; }\n"
"  HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);\n"
"  if (f == INVALID_HANDLE_VALUE) { puts(\"open failed\"); return 2; }\n"
"  DWORD sz = GetFileSize(f, 0);\n"
"  void* p = VirtualAlloc(0, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
"  DWORD rd; ReadFile(f, p, sz, &rd, 0); CloseHandle(f);\n"
"  printf(\"[launcher] %s loaded at %p, size %u\\n\", argv[1], p, sz);\n"
"  ((fn)p)();\n"
"  printf(\"[launcher] returned\\n\");\n"
"  return 0;\n"
"}\n")
add_executable(launcher "${CMAKE_BINARY_DIR}/launcher.c")
target_link_libraries(launcher PRIVATE kernel32)
