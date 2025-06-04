cmake_minimum_required(VERSION 3.10)
project(dns_relay_server C)

set(CMAKE_C_STANDARD 11)

# 添加所有源文件
add_executable(dns_relay_server
    main.c
        request_handler.c
        request_handler.h
        forwarder.c
        forwarder.h
        dns_cache.c
        dns_cache.h
        dns_protocol.c
        dns_protocol.h
        common.h
)


# Windows特定设置
if(WIN32)
    target_link_libraries(dns_relay_server wsock32 ws2_32)
endif()

# 设置编译选项
if(MSVC)
    target_compile_options(dns_relay_server PRIVATE /W4)
else()
    target_compile_options(dns_relay_server PRIVATE -Wall -Wextra)
endif()

# 复制配置文件到构建目录
configure_file(${CMAKE_SOURCE_DIR}/dnsrelay.txt ${CMAKE_BINARY_DIR}/dnsrelay.txt COPYONLY)
