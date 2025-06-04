//forwarder.c
#include "forwarder.h"

void forward_to_external_dns(SOCKET_TYPE main_sockfd_param, // 客户端连接的main_sockfd
                             const unsigned char* request, int len,
                             const struct sockaddr_in* client_addr, socklen_t client_addr_len,
                             int qname_len_for_servfail,
                             char* upstream_server_info) { // upstream_server_info is now just for logging
    // 存储DNS转发服务器信息(提供给外部)
    if (upstream_server_info) {
        strncpy(upstream_server_info, EXTERNAL_DNS_SERVER, MAX_UPSTREAM_INFO_LEN);
        upstream_server_info[MAX_UPSTREAM_INFO_LEN - 1] = '\0';
    }
    struct sockaddr_in external_dns_addr;
    memset(&external_dns_addr, 0, sizeof(external_dns_addr));
    external_dns_addr.sin_family = AF_INET;
    external_dns_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, EXTERNAL_DNS_SERVER, &external_dns_addr.sin_addr) <= 0) {
        perror("inet_pton failed for external DNS server");
        // 调用send_servfail_response的参数
        uint16_t original_id = ((DNSHeader*)request)->id;
        const unsigned char* qname_start_ptr = request + sizeof(DNSHeader);
        send_servfail_response(main_sockfd_param, original_id, qname_start_ptr, qname_len_for_servfail,
                               client_addr, client_addr_len);
        return;
    }

    SOCKET_TYPE forward_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (forward_sockfd == INVALID_SOCKET) {

        perror("Failed to create forward socket");
        uint16_t original_id = ((DNSHeader*)request)->id;
        const unsigned char* qname_start_ptr = request + sizeof(DNSHeader);
        send_servfail_response(main_sockfd_param, original_id, qname_start_ptr, qname_len_for_servfail,
                               client_addr, client_addr_len);
        return;
    }

    DWORD timeout_val = FORWARD_TIMEOUT_SEC * 1000;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_val, sizeof(timeout_val)) < 0) {
        printf("setsockopt SO_RCVTIMEO failed (Windows): %d\n", GET_LAST_ERROR);
        // 设置超时失败，继续执行
    }

    // ... existing code ...
    int retries = 0;
    while (retries < MAX_RETRIES) {
        // 尝试发送请求到外部DNS
        if (sendto(forward_sockfd, (const char *) request, len, 0,
                   (struct sockaddr *) &external_dns_addr, sizeof(external_dns_addr)) < 0) {
            perror("sendto external DNS failed");
            retries++;
            if (retries < MAX_RETRIES) {
                Sleep(100); // 重试前等待
            }
            continue; // 重试发送
        }

        // sendto成功，现在等待响应
        unsigned char response_buffer[DNS_BUFFER_SIZE];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        int resp_len = recvfrom(forward_sockfd, (char *) response_buffer, sizeof(response_buffer), 0,
                                (struct sockaddr *) &from_addr, &from_len);

        if (resp_len > 0) {
            // 检查响应ID是否与请求ID匹配
            if (resp_len >= (int) sizeof(DNSHeader) &&
                ((DNSHeader *) response_buffer)->id == ((DNSHeader *) request)->id) {
                // 成功响应转发给原客户端
                if (sendto(main_sockfd_param, (char *) response_buffer, resp_len, 0,
                           (struct sockaddr *) client_addr, client_addr_len) < 0) {
                    perror("sendto original client failed");
                } else {
                    printf("Forwarded external response (ID: %u) to %s:%d\n",
                           ntohs(((DNSHeader *) response_buffer)->id),
                           inet_ntoa(client_addr->sin_addr),
                           ntohs(client_addr->sin_port));
                }
                CLOSE_SOCKET(forward_sockfd);
                return; // 成功完成
            } else {
                printf("External DNS response ID mismatch, invalid response, retrying...\n");
            }
        } else {
            // recvfrom失败或超时
            if (GET_LAST_ERROR == WSAETIMEDOUT) {
                printf("Timeout waiting for external DNS response, retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                printf("recvfrom external DNS failed with error: %d. Retrying...\n", GET_LAST_ERROR);
            }
        }

        retries++;
        if (retries < MAX_RETRIES) {
            Sleep(100); // 重试前等待
        }
    }

// 所有重试都失败了
    fprintf(stderr, "External DNS query failed after %d retries (ID: %u)\n", MAX_RETRIES, ntohs(((DNSHeader *) request)->id));
    uint16_t original_id = ((DNSHeader *) request)->id;
    const unsigned char *qname_start_ptr = request + sizeof(DNSHeader);
    send_servfail_response(main_sockfd_param, original_id, qname_start_ptr, qname_len_for_servfail,
                           client_addr, client_addr_len);
    CLOSE_SOCKET(forward_sockfd);
}