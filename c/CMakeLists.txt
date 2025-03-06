cmake_minimum_required(VERSION 3.17)

project(receiver C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/libuwsc/cmake/Modules/")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/libuwsc/src/ssl/cmake/Modules/")


set(C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

find_package(Libev REQUIRED)
find_package(MbedTLS REQUIRED)

add_executable(receiver
    receiver.c
)

target_include_directories(receiver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/libuwsc/a/usr/local/include
    ${LIBEV_INCLUDE_DIR}
    ${MBEDTLS_INCLUDE_DIR}
)
target_link_libraries(
    receiver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/libuwsc/build/src/libuwsc.a
    ${LIBEV_LIBRARY}
    ${MBEDTLS_LIBRARY}
    ${MBEDX509_LIBRARY}
    ${MBEDCRYPTO_LIBRARY}
)
