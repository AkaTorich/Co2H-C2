cmake_minimum_required(VERSION 3.24)
project(co2h_plugin_screenshot_gallery LANGUAGES CXX)

find_package(Qt6 6.4 COMPONENTS Core Gui Widgets Svg REQUIRED)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)

add_library(co2h_plugin_screenshot_gallery SHARED
    ScreenshotGalleryPlugin.cpp
)

target_link_libraries(co2h_plugin_screenshot_gallery PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Svg
)

# Import-библиотека клиента (содержит экспортированные символы PluginContext).
if(CO2H_CLIENT_LIB)
    target_link_libraries(co2h_plugin_screenshot_gallery PRIVATE "${CO2H_CLIENT_LIB}")
endif()

set_target_properties(co2h_plugin_screenshot_gallery PROPERTIES
    OUTPUT_NAME "screenshot_gallery"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)
