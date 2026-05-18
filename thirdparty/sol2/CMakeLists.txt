# sol2 — header-only C++ binding for Lua.
cmake_minimum_required(VERSION 3.16)

include(FetchContent)
FetchContent_Declare(sol2_src
    GIT_REPOSITORY https://github.com/ThePhD/sol2.git
    GIT_TAG        v3.3.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(sol2_src)

# sol2 creates a target "sol2" automatically via its own CMakeLists.
# We just re-export it as sol2::sol2 for consistency.
if(NOT TARGET sol2::sol2)
    add_library(sol2::sol2 ALIAS sol2)
endif()
