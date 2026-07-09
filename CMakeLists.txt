cmake_minimum_required(VERSION 3.15)
project(auth-wg C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add the server subdirectory (Linux specific)
add_subdirectory(server)

# Add the client subdirectory
add_subdirectory(client)
