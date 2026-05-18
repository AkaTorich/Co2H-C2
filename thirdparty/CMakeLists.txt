# Third-party dependencies (vendored locally, no network required).

# ---- spdlog ----------------------------------------------------------------
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL       OFF CACHE BOOL "" FORCE)
add_subdirectory(spdlog)

# ---- toml++ ----------------------------------------------------------------
add_subdirectory(tomlplusplus)

# ---- msgpack-c -------------------------------------------------------------
set(MSGPACK_BUILD_DOCS     OFF CACHE BOOL "" FORCE)
set(MSGPACK_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(MSGPACK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(MSGPACK_ENABLE_CXX     OFF CACHE BOOL "" FORCE)
add_subdirectory(msgpack-c)

# ---- asio (header-only) ----------------------------------------------------
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/asio/asio/include)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
if(WIN32)
    target_link_libraries(asio INTERFACE ws2_32 mswsock)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(asio INTERFACE Threads::Threads)
endif()
add_library(asio::asio ALIAS asio)

# ---- sqlite3 ---------------------------------------------------------------
add_subdirectory(sqlite)

# ---- Lua 5.4 (for client scripting engine) ---------------------------------
add_subdirectory(lua)
