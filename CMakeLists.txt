cmake_minimum_required(VERSION 3.25)
project(RustyDolphin VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "RustyDolphin currently targets Windows because capture and process discovery use Windows APIs.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Use an x64 CMake generator. The bundled Npcap libraries are x64.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/RustyDolphin")
file(GLOB_RECURSE RD_APP_SOURCES CONFIGURE_DEPENDS "${RD_ROOT}/src/*.cpp")
set(RD_VENDOR_SOURCES
    "${RD_ROOT}/deps/dearimgui/imgui.cpp"
    "${RD_ROOT}/deps/dearimgui/imgui_draw.cpp"
    "${RD_ROOT}/deps/dearimgui/imgui_tables.cpp"
    "${RD_ROOT}/deps/dearimgui/imgui_widgets.cpp"
    "${RD_ROOT}/deps/dearimgui/backends/imgui_impl_glfw.cpp"
    "${RD_ROOT}/deps/dearimgui/backends/imgui_impl_opengl3.cpp"
    "${RD_ROOT}/deps/file dialog/ImGuiFileDialog.cpp")

add_executable(RustyDolphin ${RD_APP_SOURCES} ${RD_VENDOR_SOURCES})
set_target_properties(RustyDolphin PROPERTIES
    WIN32_EXECUTABLE "$<CONFIG:Release>"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_compile_definitions(RustyDolphin PRIVATE _UNICODE UNICODE _CONSOLE)
target_compile_options(RustyDolphin PRIVATE /W4 /WX /permissive- /sdl /external:W0)
target_include_directories(RustyDolphin SYSTEM PRIVATE
    "${RD_ROOT}/deps/npcap/Include"
    "${RD_ROOT}/deps/json/Include"
    "${RD_ROOT}/deps/dearimgui"
    "${RD_ROOT}/deps/dearimgui/backends"
    "${RD_ROOT}/deps/glfw/include"
    "${RD_ROOT}/deps/stb"
    "${RD_ROOT}/deps/file dialog")
target_link_libraries(RustyDolphin PRIVATE
    "${RD_ROOT}/deps/npcap/Lib/x64/Packet.lib"
    "${RD_ROOT}/deps/npcap/Lib/x64/wpcap.lib"
    "${RD_ROOT}/deps/glfw/lib-vc2022/glfw3.lib"
    iphlpapi ws2_32 opengl32 winhttp)

add_custom_command(TARGET RustyDolphin POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${RD_ROOT}/deps/assets" "$<TARGET_FILE_DIR:RustyDolphin>/deps/assets"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${RD_ROOT}/deps/fonts" "$<TARGET_FILE_DIR:RustyDolphin>/deps/fonts"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${RD_ROOT}/deps/manuf" "$<TARGET_FILE_DIR:RustyDolphin>/deps/manuf")

include(CTest)
if(BUILD_TESTING)
    add_executable(RustyDolphinTests
        RustyDolphin/tests/CoreTests.cpp
        RustyDolphin/src/Core/PacketDecoder.cpp
        RustyDolphin/src/Core/FilterParser.cpp)
    target_include_directories(RustyDolphinTests PRIVATE "${RD_ROOT}/src")
    target_compile_options(RustyDolphinTests PRIVATE /W4 /WX /permissive-)
    add_test(NAME core-parser-tests COMMAND RustyDolphinTests)
endif()
