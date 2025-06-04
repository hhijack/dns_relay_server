// main.c
#include "common.h"          // 包含常用头文件、宏定义、跨平台兼容性处理
#include "dns_cache.h"       // 加载和查找本地 DNS 映射表
#include "request_handler.h" // 定义 RequestInfo 结构体和 handle_request 线程函数
#include "dns_protocol.h"    // DNS 协议解析与响应构造函数

int main() {
    WSADATA wsaData; // Winsock 初始化信息结构体

    // 初始化 Winsock 库（Windows 平台）
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", GET_LAST_ERROR);
        return 1; // 如果失败，退出程序
    }

    // 从 dnsrelay.txt 加载本地 DNS 映射规则
    load_dns_table("dnsrelay.txt");

    // 初始化随机数生成器（目前未使用，为后续功能预留）
    srand(time(NULL));

    SOCKET_TYPE local_main_sockfd; // 主 socket 描述符

    // 创建 UDP socket（SOCK_DGRAM 表示 UDP）
    local_main_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // 检查 socket 是否创建成功
    if(local_main_sockfd == INVALID_SOCKET) {
        perror("socket creation failed");
        WSACleanup(); // 清理 Winsock 资源
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr; // 服务器地址结构体

    // 设置服务器地址信息
    memset(&servaddr, 0, sizeof(servaddr)); // 清空结构体
    servaddr.sin_family = AF_INET;          // IPv4 地址族
    servaddr.sin_addr.s_addr = INADDR_ANY;  // 监听所有 IP 地址
    servaddr.sin_port = htons(53);          // 绑定到 DNS 标准端口 53

    // 将 socket 绑定到指定地址和端口
    if(bind(local_main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR) {
        printf("bind failed! Error Code: %d\n", GET_LAST_ERROR);
        perror("bind failed (make sure you have admin privileges to bind port 53 or the port is not occupied)");
        CLOSE_SOCKET(local_main_sockfd); // 关闭 socket
        WSACleanup();                    // 清理 Winsock
        exit(EXIT_FAILURE);
    }

    // 输出服务启动提示
    printf("DNS Relay Server running on port 53...\n");

    // 进入主循环，持续接收客户端请求
    while(1) {
        // 分配内存用于保存请求信息（传递给线程）
        RequestInfo* info = malloc(sizeof(RequestInfo));
        if (!info) {
            perror("Failed to allocate memory for request info");
            Sleep(100); // 内存分配失败时短暂等待
            continue;   // 不要因为一次失败就退出程序
        }

        // 初始化客户端地址长度
        info->client_addr_len = sizeof(info->client_addr);

        // 保存主 socket，供子线程发送响应使用
        info->server_sockfd = local_main_sockfd;

        // 接收来自客户端的 DNS 请求数据包
        info->len = recvfrom(
                local_main_sockfd,
                (char*)info->buffer,
                DNS_BUFFER_SIZE,
                0,
                (struct sockaddr*)&(info->client_addr),
                &(info->client_addr_len)
        );

        // 检查接收是否出错
        if(info->len == SOCKET_ERROR) {
            perror("recvfrom failed");
            free(info); // 释放内存
            continue;
        }

        // 检查接收到的数据是否小于 DNS 报文头部大小
        if (info->len < (int)sizeof(DNSHeader)) {
            fprintf(stderr, "Received packet too small for DNS header (%d bytes).\n", info->len);
            free(info);
            continue;
        }

        // 创建线程来处理请求
        pthread_t thread;
        if(pthread_create(&thread, NULL, handle_request, info) != 0) {
            perror("Failed to create thread");
            free(info); // 线程创建失败时释放内存
        } else {
            pthread_detach(thread); // 分离线程，使其结束后自动释放资源
        }
    }

    // 关闭主 socket
    CLOSE_SOCKET(local_main_sockfd);

    // 清理 Winsock 资源
    WSACleanup();

    return 0;
}
