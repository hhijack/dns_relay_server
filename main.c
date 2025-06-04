//main.c
#include "common.h"
#include "dns_cache.h"
#include "request_handler.h" // 包含RequestInfo和handle_request
#include "dns_protocol.h"

// 全局变量声明(与原代码相同)
// 注意：避免使用全局变量，需要通过RequestInfo结构体传递给handle_request
// 如果handle_request需要访问这些变量
// 可以通过RequestInfo结构体传递
// SOCKET_TYPE main_sockfd; // 改为main函数的局部变量，通过RequestInfo传递

int main() {

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", GET_LAST_ERROR);
        return 1;
    }

    load_dns_table("dnsrelay.txt");
    srand(time(NULL)); // 初始化随机数生成器(当前代码未使用，为后续扩展保留)

    SOCKET_TYPE local_main_sockfd; // 使用局部变量存储套接字

    local_main_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(local_main_sockfd == INVALID_SOCKET) {

        perror("socket creation failed");

        WSACleanup();

        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY; // 监听所有网络接口
    servaddr.sin_port = htons(53);         // DNS标准端口

    if(bind(local_main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR) {

        printf("bind failed! Error Code: %d\n", GET_LAST_ERROR);
        perror("bind failed (确保有管理员权限绑定53端口或端口未被占用)");
        CLOSE_SOCKET(local_main_sockfd);

        WSACleanup();

        exit(EXIT_FAILURE);
    }

    printf("DNS Relay Server running on port 53...\n");
    while(1) {
        RequestInfo* info = malloc(sizeof(RequestInfo));
        if (!info) {
            perror("Failed to allocate memory for request info");
            // 内存分配失败时短暂等待
            Sleep(100);

            continue; // 不要因为一次分配失败就退出程序
        }
        info->client_addr_len = sizeof(info->client_addr);
        info->server_sockfd = local_main_sockfd; // 将主套接字传递给处理函数

        info->len = recvfrom(local_main_sockfd, (char*)info->buffer, DNS_BUFFER_SIZE, 0,
                             (struct sockaddr*)&(info->client_addr), &(info->client_addr_len));

        if(info->len == SOCKET_ERROR) {

            perror("recvfrom failed");
            free(info);
            // 可以添加休眠或更详细的日志记录
            continue;
        }

        if (info->len < (int)sizeof(DNSHeader)) { // 接收的DNS数据包太小
            fprintf(stderr, "Received packet too small for DNS header (%d bytes).\n", info->len);
            free(info);
            continue;
        }

        pthread_t thread;
        if(pthread_create(&thread, NULL, handle_request, info) != 0) {
            perror("Failed to create thread");
            free(info); // 线程创建失败时释放内存
        } else {
            pthread_detach(thread); // 分离线程，使其结束后自动释放资源
        }
    }

    CLOSE_SOCKET(local_main_sockfd);

    WSACleanup();

    return 0;
}