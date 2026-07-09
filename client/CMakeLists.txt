cmake_minimum_required(VERSION 3.15)
project(vpn-client C)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "vpn-client CLI is specifically targeted for the Linux platform.")
endif()

find_package(PkgConfig REQUIRED)

pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(CJSON REQUIRED libcjson)
pkg_check_modules(LIBMNL REQUIRED libmnl)

# Reuse the embeddable-wg-library from server's third_party
set(WG_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../server/third_party/wireguard.c)

set(SOURCES
    src/main.c
    src/client_api.c
    src/client_wg.c
    ${WG_LIB_SRC}
)

add_executable(vpn-client ${SOURCES})

target_include_directories(vpn-client PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CURL_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
    ${LIBMNL_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/third_party
)

target_link_libraries(vpn-client PRIVATE
    ${CURL_LIBRARIES}
    ${CJSON_LIBRARIES}
    ${LIBMNL_LIBRARIES}
)

target_compile_options(vpn-client PRIVATE
    ${CURL_CFLAGS}
    ${CJSON_CFLAGS}
    ${LIBMNL_CFLAGS}
    -Wall -Wextra -Wno-unused-parameter
)
