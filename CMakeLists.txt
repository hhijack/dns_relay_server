cmake_minimum_required(VERSION 3.28)
project(dns_relay_server C)

set(CMAKE_C_STANDARD 11)

# 添加Windows特定设置
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lws2_32")
endif()

add_executable(dns_relay_server main.c)

# 显式链接Windows Socket库
if(WIN32)
    target_link_libraries(dns_relay_server ws2_32)
endif()