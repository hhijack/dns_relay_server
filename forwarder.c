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
#ifdef _WIN32
    if (forward_sockfd == INVALID_SOCKET) {
#else
        if (forward_sockfd < 0) {
#endif
        perror("Failed to create forward socket");
        uint16_t original_id = ((DNSHeader*)request)->id;
        const unsigned char* qname_start_ptr = request + sizeof(DNSHeader);
        send_servfail_response(main_sockfd_param, original_id, qname_start_ptr, qname_len_for_servfail,
                               client_addr, client_addr_len);
        return;
    }

#ifdef _WIN32
    DWORD timeout_val = FORWARD_TIMEOUT_SEC * 1000;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_val, sizeof(timeout_val)) < 0) {
        printf("setsockopt SO_RCVTIMEO failed (Windows): %d\n", GET_LAST_ERROR);
        // 设置超时失败，继续执行
    }
#else
    struct timeval tv;
    tv.tv_sec = FORWARD_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed (POSIX)");
        // 设置超时失败，继续执行
    }
#endif

    int retries = 0;
    while (retries < MAX_RETRIES) {
        if (sendto(forward_sockfd, (const char*)request, len, 0,
                   (struct sockaddr*)&external_dns_addr, sizeof(external_dns_addr)) < 0) { // SOCKET_ERROR on Windows
            perror("sendto external DNS failed");
            retries++;
#ifdef _WIN32
            Sleep(100); // 100ms
#else
            usleep(100000); // 100ms
#endif
            continue;
        }

        unsigned char response_buffer[DNS_BUFFER_SIZE];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        int resp_len = recvfrom(forward_sockfd, (char*)response_buffer, sizeof(response_buffer), 0,
                                (struct sockaddr*)&from_addr, &from_len);

        if (resp_len > 0) {
            // 检查响应ID是否与请求ID匹配
            if (resp_len >= (int)sizeof(DNSHeader) &&
                ((DNSHeader*)response_buffer)->id == ((DNSHeader*)request)->id) {
                // 成功响应转发给原客户端
                if (sendto(main_sockfd_param, (char*)response_buffer, resp_len, 0,
                           (struct sockaddr*)client_addr, client_addr_len) < 0) { // SOCKET_ERROR on Windows
                    perror("sendto original client failed");
                } else {
                    printf("Forwarded external response (ID: %u) to %s:%d\n",
                           ntohs(((DNSHeader*)response_buffer)->id),
                           inet_ntoa(client_addr->sin_addr),
                           ntohs(client_addr->sin_port));

                    // // 响应中添加上游服务器信息 (注释掉此功能，因为它会破坏DNS包)
                    // // set_upstream_server_info现在只打印信息，不修改包
                    // // 但为了明确，这里的调用也注释掉，因为信息已在set_upstream_server_info内部打印
                    // if (upstream_server_info && strlen(upstream_server_info) > 0) {
                    //    // The function set_upstream_server_info was modified to only print.
                    //    // If you still want that print to happen based on this call:
                    //    // set_upstream_server_info(response_buffer, resp_len, upstream_server_info);
                    //    // However, the upstream_server_info string is already known (EXTERNAL_DNS_SERVER)
                    //    // So, if logging is desired here, it can be direct:
                    //    printf("Forwarded response originated from upstream: %s\n", EXTERNAL_DNS_SERVER);
                    // }
                }
                CLOSE_SOCKET(forward_sockfd);
                return;
            } else {
                printf("External DNS response ID mismatch, invalid response, retrying...\n");
                // ID不匹配，响应无效，视为失败重试
            }
        } else { // recvfrom失败超时
#ifdef _WIN32
            if (GET_LAST_ERROR == WSAETIMEDOUT) {
                printf("Timeout waiting for external DNS response, retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                printf("recvfrom external DNS failed with error: %d. Retrying...\n", GET_LAST_ERROR);
            }
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // EAGAIN and EWOULDBLOCK usually indicate timeout
                printf("Timeout waiting for external DNS response, retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                perror("Failed to receive external DNS response, retrying...");
            }
#endif
        }
        retries++;
#ifdef _WIN32
        Sleep(100); // 重试前等待
#else
        usleep(100000); // 重试前等待
#endif
    }

    // 转发查询最终失败
    fprintf(stderr, "External DNS query failed (ID: %u)\n", ntohs(((DNSHeader*)request)->id));
    uint16_t original_id = ((DNSHeader*)request)->id;
    const unsigned char* qname_start_ptr = request + sizeof(DNSHeader);
    send_servfail_response(main_sockfd_param, original_id, qname_start_ptr, qname_len_for_servfail,
                           client_addr, client_addr_len);
    CLOSE_SOCKET(forward_sockfd);
}