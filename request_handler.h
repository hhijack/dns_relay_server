#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include "common.h"

// 线程参数结构
typedef struct {
    unsigned char buffer[DNS_BUFFER_SIZE]; // 接收缓冲区
    int len;                               // 数据长度
    struct sockaddr_in client_addr;        // 客户端地址
    socklen_t client_addr_len;             // 地址长度
    SOCKET_TYPE server_sockfd;             // 主服务器socket，用于发送响应
} RequestInfo;

void* handle_request(void* arg);

#endif // REQUEST_HANDLER_H
