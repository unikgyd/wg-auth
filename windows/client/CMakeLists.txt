cmake_minimum_required(VERSION 3.15)
project(authwg-windows CXX C)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 99)

# We want a shared library (DLL)
add_library(authwg SHARED
    src/authwg.cpp
    src/win_http.cpp
    src/cJSON.c
)

target_include_directories(authwg PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link against Windows socket and HTTP libraries
target_link_libraries(authwg PRIVATE ws2_32 winhttp)

# Strip unused symbols to keep DLL small
if(MSVC)
    # Disable annoying warnings for standard C functions like sprintf/strncpy
    target_compile_definitions(authwg PRIVATE _CRT_SECURE_NO_WARNINGS)
    
    # Statically link the C Runtime (CRT) so the user doesn't need VC++ Redistributable!
    set_property(TARGET authwg PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_compile_options(authwg PRIVATE -O3 -fvisibility=hidden)
    target_link_options(authwg PRIVATE -Wl,--strip-all)
endif()
