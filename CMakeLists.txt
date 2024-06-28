cmake_minimum_required(VERSION 3.27)
project(dns_relay C)

set(CMAKE_C_STANDARD 11)

# 编译器选项配置
if(MSVC)
    add_compile_options(/utf-8)  # 应用于所有配置
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /Zi)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2)
    endif()
else()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-O0 -g)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O3)
    endif()
endif()

find_package(libhv CONFIG REQUIRED)
find_package(Cargs CONFIG REQUIRED)

add_executable(
    ${PROJECT_NAME}
    src/main.c
    src/args.c
    src/dns.c
    src/dns_server.c
    src/logger.c
    src/cache.c
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
    hv
    cargs
)