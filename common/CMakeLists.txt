find_package(OpenSSL REQUIRED)

add_library(co2h_common STATIC
    co2h/framing.cpp
    co2h/crypto.cpp
    co2h/proto.cpp
    co2h/kv.cpp
)

target_include_directories(co2h_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(co2h_common
    PUBLIC  OpenSSL::SSL OpenSSL::Crypto
    PRIVATE spdlog::spdlog
)

if(WIN32)
    target_link_libraries(co2h_common PUBLIC ws2_32 crypt32)
endif()

add_library(co2h::common ALIAS co2h_common)
