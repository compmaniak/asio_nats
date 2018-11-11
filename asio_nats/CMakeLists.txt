cmake_minimum_required(VERSION 3.0)

project(asio-nats-client LANGUAGES CXX)

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL)

add_library(asio_nats INTERFACE)
target_link_libraries(asio_nats INTERFACE ${Boost_SYSTEM_LIBRARY} ${OPENSSL_LIBRARIES})
if (WIN32)
    target_link_libraries(asio_nats INTERFACE ws2_32)
endif()
target_include_directories(asio_nats INTERFACE
    "${Boost_INCLUDE_DIRS}"
    "${CMAKE_CURRENT_LIST_DIR}/include")
