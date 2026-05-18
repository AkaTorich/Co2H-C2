# Lua 5.4.7 — vendored source (thirdparty/lua/src/).
cmake_minimum_required(VERSION 3.16)

set(LUA_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

file(GLOB LUA_CORE_SRC "${LUA_SRC_DIR}/*.c")
# Remove standalone interpreters.
list(FILTER LUA_CORE_SRC EXCLUDE REGEX "lua\\.c$")
list(FILTER LUA_CORE_SRC EXCLUDE REGEX "luac\\.c$")

add_library(lua_static STATIC ${LUA_CORE_SRC})
target_include_directories(lua_static PUBLIC "${LUA_SRC_DIR}")

if(UNIX)
    target_compile_definitions(lua_static PRIVATE LUA_USE_POSIX LUA_USE_DLOPEN)
    target_link_libraries(lua_static PRIVATE m dl)
endif()

if(MSVC)
    target_compile_options(lua_static PRIVATE /W0)
else()
    target_compile_options(lua_static PRIVATE -w)
endif()

add_library(lua::lua ALIAS lua_static)
