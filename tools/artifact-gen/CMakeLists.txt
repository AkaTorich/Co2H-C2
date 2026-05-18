set(ARTGEN_RC_FILES "")
if(WIN32)
    set(ARTGEN_RC_FILES artifact-gen.rc)
endif()

add_executable(artifact_gen
    main.cpp
    PatchBeacon.cpp
    Wrappers.cpp
    ${ARTGEN_RC_FILES}
)

set_target_properties(artifact_gen PROPERTIES
    OUTPUT_NAME "artifact-gen"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(artifact_gen PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(artifact_gen PRIVATE
    co2h_common
)
