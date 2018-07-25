cmake_minimum_required(VERSION 3.0)

project(asio-nats LANGUAGES CXX)

add_subdirectory(asio_nats)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -Wextra $ENV{CXXFLAGS}")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")

add_executable(parser_test test/parser_test.cpp)
target_link_libraries(parser_test PUBLIC asio_nats)

add_executable(io_sync_test test/io_sync_test.cpp)
target_link_libraries(io_sync_test PUBLIC asio_nats)
target_compile_options(io_sync_test PUBLIC -Werror)

enable_testing()
add_test(NAME parser_test COMMAND parser_test)
add_test(NAME io_sync_test COMMAND io_sync_test)
