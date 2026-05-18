# Builds the position-independent loader stub for the active architecture.
# Architecture is determined by the generator/platform passed to cmake.
# After link, runs extract_text to dump the .text section into stub_<arch>.bin
# placed in ${SCELOT_STUBS_DIR} (defaults to <source>/../stubs).
cmake_minimum_required(VERSION 3.20)
project(scelot_loader C ASM_MASM)

if(NOT MSVC)
    message(FATAL_ERROR "loader stub requires MSVC")
endif()

# Pick prologue and arch-name based on pointer size.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(SCELOT_ARCH "x64")
    set(PROLOGUE_ASM prologue_x64.asm)
else()
    set(SCELOT_ARCH "x86")
    set(PROLOGUE_ASM prologue_x86.asm)
endif()

set(STUBS_DIR "${CMAKE_SOURCE_DIR}/../stubs"  CACHE PATH  "Where to drop stub_*.bin")
set(GEN_DIR   "${CMAKE_SOURCE_DIR}/../generator")

# Tiny host-tool that extracts .text section from a PE.
add_executable(extract_text "${GEN_DIR}/tools/extract_text.c")
set_target_properties(extract_text PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY                "${CMAKE_BINARY_DIR}/host"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${CMAKE_BINARY_DIR}/host"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_BINARY_DIR}/host"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/host"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL     "${CMAKE_BINARY_DIR}/host")

# The stub itself: prologue ASM must come first so its bytes occupy offset
# 0 of .text. Custom strict flags: no CRT, no GS, no RTTI, no exceptions,
# no default lib.
add_executable(stub
    "${PROLOGUE_ASM}"
    entry.c
    peb.c
    map_pe.c
    host_clr.c
    "${GEN_DIR}/aes.c"
)
target_include_directories(stub PRIVATE
    "${CMAKE_SOURCE_DIR}"
    "${GEN_DIR}")
target_compile_options(stub PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O2>
    $<$<COMPILE_LANGUAGE:C>:/Oi>
    $<$<COMPILE_LANGUAGE:C>:/GS->
    $<$<COMPILE_LANGUAGE:C>:/GR->
    $<$<COMPILE_LANGUAGE:C>:/EHs-c->
    $<$<COMPILE_LANGUAGE:C>:/Zl>
    $<$<COMPILE_LANGUAGE:C>:/TC>)
# SCELOT_TRACE можно включить для отладки — пишет лог в %TEMP%\scelot_clr_trace.txt.
# target_compile_definitions(stub PRIVATE SCELOT_TRACE=1)
target_link_options(stub PRIVATE
    /NODEFAULTLIB
    /ENTRY:_scelot_entry
    /SUBSYSTEM:CONSOLE
    /BASE:0x10000000 /FIXED
    # /FIXED несовместим с /DYNAMICBASE (новые MSVC BuildTools включают его
    # по умолчанию). Явно отключаем ASLR — лоадер всё равно position-independent.
    /DYNAMICBASE:NO
    # /SAFESEH (Safe SEH) у x86 включён по умолчанию в свежих BuildTools и
    # требует регистрации SEH-обработчиков в .sxdata. Наш prologue_x86.asm
    # написан вручную, без SEH-записей — отключаем (на x64 флаг игнорируется).
    /SAFESEH:NO
    /MERGE:.rdata=.text
    /MERGE:.data=.text
    /SECTION:.text,RWE
    /INCREMENTAL:NO
    /NOCOFFGRPINFO
    /OPT:NOREF
    /OPT:NOICF
    # LNK4254 — намеренное слияние .data в .text с переустановкой атрибутов
    # на RWE; LNK4281 — намеренный фиксированный базовый адрес ниже 4 ГБ.
    /IGNORE:4254
    /IGNORE:4281)
set_target_properties(stub PROPERTIES
    OUTPUT_NAME "stub_${SCELOT_ARCH}"
    LINKER_LANGUAGE C)

file(MAKE_DIRECTORY "${STUBS_DIR}")

# After build, run extract_text on the stub PE to produce stub_<arch>.bin.
add_custom_command(TARGET stub POST_BUILD
    COMMAND "${CMAKE_BINARY_DIR}/host/extract_text"
            "$<TARGET_FILE:stub>"
            "${STUBS_DIR}/stub_${SCELOT_ARCH}.bin"
    BYPRODUCTS "${STUBS_DIR}/stub_${SCELOT_ARCH}.bin"
    COMMENT "extracting .text -> stub_${SCELOT_ARCH}.bin"
    VERBATIM)
add_dependencies(stub extract_text)
