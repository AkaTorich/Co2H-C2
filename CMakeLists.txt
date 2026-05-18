cmake_minimum_required(VERSION 3.24)

# msgpack-c использует cmake_minimum_required(VERSION 2.8) — CMake 4.x это отвергает.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
project(Co2H
    VERSION 0.1.0
    DESCRIPTION "Co2H C2 framework"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(CO2H_BUILD_SERVER   "Build teamserver"              ON)
option(CO2H_BUILD_CLIENT   "Build Qt6 operator client"     ON)
option(CO2H_BUILD_BEACON   "Build Windows beacon (MSVC)"   ON)
option(CO2H_BUILD_TOOLS    "Build artifact-gen and tools"  ON)
option(CO2H_BUILD_TESTS    "Build unit tests"              OFF)

# OpenSSL нужен только серверу и клиенту; бикон использует bcrypt.
if(CO2H_BUILD_SERVER OR CO2H_BUILD_CLIENT OR CO2H_BUILD_TOOLS)
    find_package(OpenSSL REQUIRED)
endif()

# Бикон — только Windows (DLL/EXE implant).
# artifact-gen — кроссплатформенный, собирается и на Linux.
if(NOT WIN32)
    set(CO2H_BUILD_BEACON OFF CACHE BOOL "" FORCE)
endif()

if(WIN32)
    add_compile_definitions(
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
    if(MSVC)
        # Не применять флаги C/C++-компилятора к MASM-исходникам,
        # иначе ml64.exe выбрасывает A4018 и не создаёт .obj.
        add_compile_options(
            $<$<COMPILE_LANGUAGE:C,CXX>:/W4>
            $<$<COMPILE_LANGUAGE:C,CXX>:/permissive->
            $<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>
            $<$<COMPILE_LANGUAGE:C,CXX>:/Zc:__cplusplus>
        )
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_subdirectory(thirdparty)

# common зависит от OpenSSL — подключаем только когда нужен сервер/клиент/инструменты.
if(CO2H_BUILD_SERVER OR CO2H_BUILD_CLIENT OR CO2H_BUILD_TOOLS)
    add_subdirectory(common)
endif()

if(CO2H_BUILD_SERVER)
    add_subdirectory(server)
endif()

if(CO2H_BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(CO2H_BUILD_BEACON AND WIN32 AND MSVC)
    add_subdirectory(beacon)
endif()

# Artifact Kit — EXE-stub шаблон. Только Windows MSVC.
# Перенесён из tools/beacon-stub в kit/artifact/exe_basic как часть Kit-структуры
# (рядом с sleepmask/, processinject/, bof/, и т.д.).
if(CO2H_BUILD_TOOLS AND WIN32 AND MSVC)
    add_subdirectory(kit/artifact/exe_basic)
endif()

# artifact-gen — чистый C++, собирается на любой платформе.
if(CO2H_BUILD_TOOLS)
    add_subdirectory(tools/artifact-gen)
endif()

if(CO2H_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

message(STATUS "Co2H ${PROJECT_VERSION}")
message(STATUS "  server: ${CO2H_BUILD_SERVER}")
message(STATUS "  client: ${CO2H_BUILD_CLIENT}")
message(STATUS "  beacon: ${CO2H_BUILD_BEACON}")
message(STATUS "  tools : ${CO2H_BUILD_TOOLS}")
