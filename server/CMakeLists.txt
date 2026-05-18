set(SERVER_RC_FILES "")
if(WIN32)
    set(SERVER_RC_FILES server.rc)
endif()

add_executable(co2h_server
    main.cpp
    ${SERVER_RC_FILES}
    Config.cpp
    Core.cpp
    db/Database.cpp
    auth/OperatorAuth.cpp
    net/OperatorAcceptor.cpp
    net/OperatorSession.cpp
    core/ListenerManager.cpp
    core/SessionRegistry.cpp
    core/TaskQueue.cpp
    listeners/https/HttpsListener.cpp
    listeners/https/MalleableProfile.cpp
    listeners/https/BeaconCrypto.cpp
    listeners/https/RsaOaep.cpp
    listeners/pivot/PivotListener.cpp
    listeners/tcp/TcpListener.cpp
    listeners/smb/SmbListener.cpp
    listeners/dns/DnsListener.cpp
    listeners/socks5/Socks5Listener.cpp
    listeners/rportfwd/RportfwdListener.cpp
)

target_include_directories(co2h_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(co2h_server
    PRIVATE co2h::common
            OpenSSL::SSL OpenSSL::Crypto
            asio::asio
            sqlite3::sqlite3
            spdlog::spdlog
            tomlplusplus::tomlplusplus
)

if(WIN32)
    target_link_libraries(co2h_server PRIVATE bcrypt)
endif()

if(MSVC)
    set_target_properties(co2h_server PROPERTIES OUTPUT_NAME "teamserver")
else()
    set_target_properties(co2h_server PROPERTIES OUTPUT_NAME "teamserver")
endif()
