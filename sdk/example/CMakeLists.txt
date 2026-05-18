cmake_minimum_required(VERSION 3.24)
project(my_plugin LANGUAGES CXX)

# Qt6 — должна совпадать с версией, которой собран клиент.
find_package(Qt6 6.4 COMPONENTS Core Gui Widgets Svg REQUIRED)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)

# Путь к SDK-заголовкам (IClientPlugin.hpp, PluginContext.hpp).
set(CO2H_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../include")

# Import-библиотека клиента (co2h-client.lib).
# При сборке: cmake -B build -DCO2H_CLIENT_LIB=../lib/co2h-client.lib
if(NOT CO2H_CLIENT_LIB)
    # По умолчанию — рядом в sdk/lib/
    set(CO2H_CLIENT_LIB "${CMAKE_CURRENT_SOURCE_DIR}/../lib/co2h-client.lib")
endif()

add_library(my_plugin SHARED ExamplePlugin.cpp)

target_include_directories(my_plugin PRIVATE ${CO2H_SDK_DIR})

target_link_libraries(my_plugin PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Svg
)

# На Windows линкуемся с import-библиотекой клиента.
# На Linux не нужно — символы доступны через -rdynamic.
if(WIN32 AND EXISTS "${CO2H_CLIENT_LIB}")
    target_link_libraries(my_plugin PRIVATE "${CO2H_CLIENT_LIB}")
endif()

# Итоговая DLL кладётся в plugins/ рядом с co2h-client.
set_target_properties(my_plugin PROPERTIES
    OUTPUT_NAME "my_plugin"
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)
