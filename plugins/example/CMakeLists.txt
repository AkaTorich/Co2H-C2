cmake_minimum_required(VERSION 3.24)
project(co2h_plugin_example LANGUAGES CXX)

find_package(Qt6 6.4 COMPONENTS Core Gui Widgets Svg REQUIRED)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)

add_library(co2h_plugin_example SHARED ExamplePlugin.cpp)

target_link_libraries(co2h_plugin_example PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Svg
)

# Import-библиотека клиента (содержит экспортированные символы PluginContext).
# При сборке из build.ps1 / build-linux.sh передаётся через -DCO2H_CLIENT_LIB=...
if(CO2H_CLIENT_LIB)
    target_link_libraries(co2h_plugin_example PRIVATE "${CO2H_CLIENT_LIB}")
endif()

# Plugin DLL goes into the plugins/ subdirectory next to co2h-client.
set_target_properties(co2h_plugin_example PROPERTIES
    OUTPUT_NAME "example_recon"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)
