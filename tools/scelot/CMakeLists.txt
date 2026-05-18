# Top-level scelot generator. Builds scelot.exe from generator/*.c plus a
# generated embed.c that contains the two loader stub blobs.
#
# This project EXPECTS the stubs to be already built. Run build.cmd from
# the project root — it invokes CMake three times in the right order:
#   1. loader (x64) -> stubs/stub_x64.bin
#   2. loader (x86) -> stubs/stub_x86.bin
#   3. top-level    -> scelot.exe
cmake_minimum_required(VERSION 3.20)
project(scelot C RC)

set(CMAKE_C_STANDARD 11)
set(STUBS_DIR "${CMAKE_SOURCE_DIR}/stubs")
set(STUB_X64_BIN "${STUBS_DIR}/stub_x64.bin")
set(STUB_X86_BIN "${STUBS_DIR}/stub_x86.bin")

if(NOT EXISTS "${STUB_X64_BIN}" OR NOT EXISTS "${STUB_X86_BIN}")
    message(FATAL_ERROR
        "stub blobs missing in ${STUBS_DIR}. Run build.cmd from the project "
        "root; it builds loader stubs first and then re-invokes this CMake.")
endif()

# Generate embed.c from the two stub blobs.
set(GEN_EMBED_C "${CMAKE_BINARY_DIR}/embed.c")
add_custom_command(
    OUTPUT  "${GEN_EMBED_C}"
    COMMAND "${CMAKE_COMMAND}"
            -DOUT=${GEN_EMBED_C}
            -DX64=${STUB_X64_BIN}
            -DX86=${STUB_X86_BIN}
            -P  "${CMAKE_SOURCE_DIR}/cmake/gen_embed.cmake"
    DEPENDS "${STUB_X64_BIN}" "${STUB_X86_BIN}"
            "${CMAKE_SOURCE_DIR}/cmake/gen_embed.cmake"
    COMMENT "embedding stub blobs into embed.c"
    VERBATIM
)

add_executable(scelot
    generator/main.c
    generator/aes.c
    generator/rng.c
    generator/pe_parser.c
    generator/poly.c
    "${GEN_EMBED_C}"
    scelot.rc
)
target_include_directories(scelot PRIVATE generator)
target_link_libraries(scelot PRIVATE bcrypt user32 kernel32)
set_target_properties(scelot PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY                "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL     "${CMAKE_SOURCE_DIR}")
