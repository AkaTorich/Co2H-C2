add_executable(beacon_stub WIN32 exe_basic.c)

set_target_properties(beacon_stub PROPERTIES
    OUTPUT_NAME "beacon-stub"
    C_STANDARD 11
)

target_compile_definitions(beacon_stub PRIVATE
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
)

target_link_libraries(beacon_stub PRIVATE kernel32)

# No CRT — keep the stub lean
target_link_options(beacon_stub PRIVATE
    /SUBSYSTEM:WINDOWS
    /ENTRY:WinMainCRTStartup
)
