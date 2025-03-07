cmake_minimum_required(VERSION 3.17)
cmake_policy(SET CMP0077 NEW)

project(wsrelay C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")


set(C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Libev REQUIRED)
find_package(MbedTLS REQUIRED)
# find_package(Libuwsc REQUIRED)
find_package(Python3 3.6 COMPONENTS Interpreter REQUIRED)

set(GEN_HEADER ${CMAKE_CURRENT_BINARY_DIR}/gen.h)

add_custom_command(
    OUTPUT ${GEN_HEADER}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/cmake/gendef.py ${GEN_HEADER}
    DEPENDS ${CMAKE_SOURCE_DIR}/cmake/gendef.py
    COMMENT "Generating header file"
)

set(BUILD_STATIC 1 CACHE BOOL blah)
set(BUILD_EXAMPLE 0 CACHE BOOL blah)
set(USE_MBEDTLS 1 CACHE BOOL blah)
set(UWSC_LUA_SUPPORT_DEFAULT 0 CACHE BOOL blah)
add_subdirectory(thirdparty/libuwsc)
unset(BUILD_STATIC)
unset(BUILD_EXAMPLE)

add_executable(wsrelay-receiver
    ${CMAKE_CURRENT_BINARY_DIR}/gen.h
    totp.h
    receiver.c
)

target_include_directories(wsrelay-receiver PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBEV_INCLUDE_DIR}
    ${MBEDTLS_INCLUDE_DIR}
)
target_link_libraries(
    wsrelay-receiver PRIVATE
    uwsc
    ${LIBEV_LIBRARY}
    ${MBEDTLS_LIBRARY}
    ${MBEDX509_LIBRARY}
    ${MBEDCRYPTO_LIBRARY}
)
