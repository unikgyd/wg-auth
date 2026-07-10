cmake_minimum_required(VERSION 3.15)
project(vpn-authd C)

# Ensure server is strictly targeted for Linux platform
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "vpn-authd server is specifically targeted for the Linux platform.")
endif()

find_package(PkgConfig REQUIRED)

# Required system libraries
# Install on Ubuntu/Debian: sudo apt-get install libsodium-dev libmicrohttpd-dev libsqlite3-dev libmnl-dev libcjson-dev pkg-config
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(LIBMNL REQUIRED libmnl)
pkg_check_modules(CJSON REQUIRED libcjson)

# cJSON is now provided via system package (libcjson-dev)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
# embeddable-wg-library
set(WG_LIB_SRC ${THIRD_PARTY_DIR}/wireguard.c)

set(SOURCES
    src/main.c
    src/config.c
    src/wg_ctl.c
    src/auth.c
    src/db.c
    src/ip_pool.c
    src/api_handlers.c
    src/reaper.c
    src/util.c
    ${WG_LIB_SRC}
)

add_executable(vpn-authd ${SOURCES})

target_include_directories(vpn-authd PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${THIRD_PARTY_DIR}
    ${LIBSODIUM_INCLUDE_DIRS}
    ${MICROHTTPD_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
    ${LIBMNL_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
)

target_link_libraries(vpn-authd PRIVATE
    ${LIBSODIUM_LIBRARIES}
    ${MICROHTTPD_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    ${LIBMNL_LIBRARIES}
    ${CJSON_LIBRARIES}
)

target_compile_options(vpn-authd PRIVATE
    ${LIBSODIUM_CFLAGS}
    ${MICROHTTPD_CFLAGS}
    ${SQLITE3_CFLAGS}
    ${LIBMNL_CFLAGS}
    ${CJSON_CFLAGS}
    -Wall -Wextra -pthread -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
)

target_link_options(vpn-authd PRIVATE -pthread -Wl,-z,relro,-z,now)

# CLI tool to add users
add_executable(vpn-add-user
    src/add_user.c
    src/db.c
    src/auth.c
    src/config.c
    src/util.c
)

target_include_directories(vpn-add-user PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBSODIUM_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(vpn-add-user PRIVATE
    ${LIBSODIUM_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

target_compile_options(vpn-add-user PRIVATE
    ${LIBSODIUM_CFLAGS}
    ${SQLITE3_CFLAGS}
    -Wall -Wextra -pthread -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
)

target_link_options(vpn-add-user PRIVATE -pthread -Wl,-z,relro,-z,now)
