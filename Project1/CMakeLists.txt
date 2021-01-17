cmake_minimum_required(VERSION 2.8)
set (CMAKE_CXX_STANDARD 11)

project( Project1 )

FILE(GLOB source src/*.cpp src/*.c)
find_package(Threads REQUIRED)

include_directories( /usr/local/ssl/include include)
add_executable( Project1 ${source} )

set(EXECUTABLE_OUTPUT_PATH ./bin)
target_link_libraries( Project1 ${CMAKE_THREAD_LIBS_INIT} /usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a )