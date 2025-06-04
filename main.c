#include "common.h"
#include "dns_cache.h"
#include "request_handler.h" // ����RequestInfo��handle_request
#include "dns_protocol.h"


// �������׽��ֵ�ȫ�ֱ���(��ԭ����ͬ)
// ����������ʹ��ȫ�ֱ�������Ҫ���䴫�ݸ�handle_request
// ������handle_request������������Ҫ���ĺ���
// ����ͨ��RequestInfo�ṹ�崫��
// SOCKET_TYPE main_sockfd; // ������Ϊmain�ľֲ�������ͨ��RequestInfo����

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", GET_LAST_ERROR);
        return 1;
    }
#endif

    load_dns_table("dnsrelay.txt");
    srand(time(NULL)); // ��ʼ��������������(��ǰ����δʹ�õ���Ϊ����ʵ������)

    SOCKET_TYPE local_main_sockfd; // ʹ�þֲ������洢���׽���

    local_main_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
    if(local_main_sockfd == INVALID_SOCKET) {
#else
        if(local_main_sockfd < 0) {
#endif
        perror("socket creation failed");
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY; // �������п��������ӿ�
    servaddr.sin_port = htons(53);         // DNS��׼�˿�

#ifdef _WIN32
    if(bind(local_main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR) {
#else
        if(bind(local_main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
#endif
        printf("bind failed! Error Code: %d\n", GET_LAST_ERROR);
        perror("bind failed (ensure you have admin privileges for port 53 or port is not in use)");
        CLOSE_SOCKET(local_main_sockfd);
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

    printf("DNS Relay Server running on port 53...\n");
    while(1) {
        RequestInfo* info = malloc(sizeof(RequestInfo));
        if (!info) {
            perror("Failed to allocate memory for request info");
            // ���������Ա�������ʧ��ʱ��æ�ȴ�
#ifdef _WIN32
            Sleep(100);
#else
            usleep(100000);
#endif
            continue; // ������һ�η���ʧ�ܾ��˳�������
        }
        info->client_addr_len = sizeof(info->client_addr);
        info->server_sockfd = local_main_sockfd; // �������׽��ִ��ݸ���������

        info->len = recvfrom(local_main_sockfd, (char*)info->buffer, DNS_BUFFER_SIZE, 0,
                             (struct sockaddr*)&(info->client_addr), &(info->client_addr_len));
#ifdef _WIN32
        if(info->len == SOCKET_ERROR) {
#else
            if(info->len < 0) {
#endif
            perror("recvfrom failed");
            free(info);
            // Potentially sleep or log more verbosely
            continue;
        }

        if (info->len < (int)sizeof(DNSHeader)) { // ��������DNS���ݰ���С����
            fprintf(stderr, "Received packet too small for DNS header (%d bytes).\n", info->len);
            free(info);
            continue;
        }


        pthread_t thread;
        if(pthread_create(&thread, NULL, handle_request, info) != 0) {
            perror("Failed to create thread");
            free(info); // Free memory if thread creation fails
        } else {
            pthread_detach(thread); // Detach the thread so resources are freed automatically
        }
    }

    CLOSE_SOCKET(local_main_sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}