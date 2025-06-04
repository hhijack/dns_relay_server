#include "forwarder.h"

void forward_to_external_dns(SOCKET_TYPE main_sockfd_param, // Renamed to avoid conflict if main_sockfd was global
                             const unsigned char* request, int len,
                             const struct sockaddr_in* client_addr, socklen_t client_addr_len,
                             int qname_len_for_servfail,
                             char* upstream_server_info) {
    // Store upstream DNS server info
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
        // Prepare parameters for send_servfail_response
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
        // Non-fatal, continue
    }
#else
    struct timeval tv;
    tv.tv_sec = FORWARD_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed (POSIX)");
        // Non-fatal, continue
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
            // Check if the response ID matches the request ID
            if (resp_len >= sizeof(DNSHeader) &&
                ((DNSHeader*)response_buffer)->id == ((DNSHeader*)request)->id) {
                // Forward the valid response back to the original client
                if (sendto(main_sockfd_param, (char*)response_buffer, resp_len, 0,
                           (struct sockaddr*)client_addr, client_addr_len) < 0) { // SOCKET_ERROR on Windows
                    perror("sendto original client failed");
                } else {
                    printf("Forwarded external response for ID %u to %s:%d\n",
                           ntohs(((DNSHeader*)response_buffer)->id),
                           inet_ntoa(client_addr->sin_addr),
                           ntohs(client_addr->sin_port));
                    
                    // Add upstream server info to response
                    if (upstream_server_info && strlen(upstream_server_info) > 0) {
                        set_upstream_server_info(response_buffer, resp_len, upstream_server_info);
                    }
                }
                CLOSE_SOCKET(forward_sockfd);
                return;
            } else {
                printf("ID mismatch or invalid response size from external DNS. Retrying...\n");
                // ID mismatch or too short response, treat as a failed attempt for retry
            }
        } else { // recvfrom failed or timed out
#ifdef _WIN32
            if (GET_LAST_ERROR == WSAETIMEDOUT) {
                printf("Timeout receiving from external DNS. Retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                printf("recvfrom external DNS failed with error: %d. Retrying...\n", GET_LAST_ERROR);
            }
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // EAGAIN and EWOULDBLOCK are typical for timeouts
                printf("Timeout receiving from external DNS. Retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                perror("recvfrom external DNS failed. Retrying...");
            }
#endif
        }
        retries++;
#ifdef _WIN32
        Sleep(100); // Wait before retrying
#else
        usleep(100000); // Wait before retrying
#endif
    }

    // All retries failed
    fprintf(stderr, "All retries failed for external DNS query (ID: %u)\n", ntohs(((DNSHeader*)request)->id));
    uint16_t original_id = ((DNSHeader*)request)->id;
    const unsigned char* qname_start_ptr = request + sizeof(DNSHeader);
    send_servfail_response(main_sockfd_param, original_id, qname_start_ptr, qname_len_for_servfail,
                           client_addr, client_addr_len);
    CLOSE_SOCKET(forward_sockfd);
}