find_package(Qt6 6.4 COMPONENTS Core Gui Widgets Svg SvgWidgets Network REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

qt_standard_project_setup()

set(CLIENT_SOURCES
    main.cpp
    App.cpp
    ui/MainWindow.cpp
    ui/LoginDialog.cpp
    ui/ConsoleWidget.cpp
    ui/SessionsView.cpp
    ui/FileBrowserView.cpp
    ui/ProcessBrowserView.cpp
    ui/ListenersView.cpp
    ui/DownloadsView.cpp
    ui/CredentialsView.cpp
    ui/AuditView.cpp
    ui/ChatView.cpp
    ui/GraphView.cpp
    ui/Theme.cpp
    ui/SvgIcon.cpp
    models/SessionsModel.cpp
    models/ListenersModel.cpp
    models/DownloadsModel.cpp
    models/CredentialsModel.cpp
    models/AuditModel.cpp
    net/ServerClient.cpp
    plugin/PluginContext.cpp
    plugin/PluginManager.cpp
    script/ScriptEngine.cpp
    ui/ScriptsView.cpp
)

set(CLIENT_HEADERS
    App.hpp
    ui/MainWindow.hpp
    ui/LoginDialog.hpp
    ui/ConsoleWidget.hpp
    ui/SessionsView.hpp
    ui/FileBrowserView.hpp
    ui/ProcessBrowserView.hpp
    ui/ListenersView.hpp
    ui/DownloadsView.hpp
    ui/CredentialsView.hpp
    ui/AuditView.hpp
    ui/ChatView.hpp
    ui/GraphView.hpp
    ui/Theme.hpp
    ui/SvgIcon.hpp
    models/SessionsModel.hpp
    models/ListenersModel.hpp
    models/DownloadsModel.hpp
    models/CredentialsModel.hpp
    models/AuditModel.hpp
    net/ServerClient.hpp
    plugin/IClientPlugin.hpp
    plugin/PluginContext.hpp
    plugin/PluginManager.hpp
    script/ScriptEngine.hpp
    ui/ScriptsView.hpp
)

set(CLIENT_RESOURCES resources/resources.qrc)
if(WIN32)
    list(APPEND CLIENT_RESOURCES resources/client.rc)
endif()

qt_add_executable(co2h_client
    ${CLIENT_SOURCES}
    ${CLIENT_HEADERS}
    ${CLIENT_RESOURCES}
)

set_target_properties(co2h_client PROPERTIES
    OUTPUT_NAME "co2h-client"
    WIN32_EXECUTABLE ON
)

target_include_directories(co2h_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# CO2H_CLIENT_BUILD — при сборке клиента PluginContext экспортируется (dllexport).
# Плагины не определяют этот макрос → получают dllimport.
target_compile_definitions(co2h_client PRIVATE CO2H_CLIENT_BUILD)

# На Windows MSVC автоматически генерирует import-библиотеку (.lib),
# когда EXE содержит dllexport-символы. Включаем ENABLE_EXPORTS.
set_target_properties(co2h_client PROPERTIES ENABLE_EXPORTS ON)

target_link_libraries(co2h_client PRIVATE
    co2h::common
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Svg Qt6::SvgWidgets Qt6::Network
    asio::asio
    OpenSSL::SSL OpenSSL::Crypto
    lua::lua
)


# На Linux: -rdynamic позволяет dlopen-плагинам видеть символы клиента.
if(UNIX AND NOT APPLE)
    target_link_options(co2h_client PRIVATE -rdynamic)
endif()
