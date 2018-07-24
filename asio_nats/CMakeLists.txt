cmake_minimum_required(VERSION 3.0)

project(asio-nats-client LANGUAGES CXX)

find_package(Boost REQUIRED COMPONENTS system)

add_library(asio_nats INTERFACE)
target_link_libraries(asio_nats INTERFACE ${Boost_SYSTEM_LIBRARY})
target_include_directories(asio_nats INTERFACE "${CMAKE_CURRENT_LIST_DIR}/include")
