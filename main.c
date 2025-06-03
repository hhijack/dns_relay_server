#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> // For InetPton, inet_ntoa
#include <windows.h>  // For Sleep (if needed, instead of unistd.h's sleep)
#pragma comment(lib, "ws2_32.lib") // Link with ws2_32.lib
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET closesocket
#define GET_LAST_ERROR WSAGetLastError()
// For pthread on Windows, you'd typically need a library like pthreads-win32
// Or use Windows native threads. This example assumes pthread types are available.
#include <pthread.h> // Assuming pthreads-win32 is set up or MinGW has a version
#else // Linux / macOS
#include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <errno.h>
    #define SOCKET_TYPE int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR   -1
    #define CLOSE_SOCKET close
    #define GET_LAST_ERROR errno
#endif


#define MAX_DNS_ENTRIES 1000
#define DNS_BUFFER_SIZE 512
//#define EXTERNAL_DNS_SERVER "8.8.8.8" // Google Public DNS or 114.114.114.114
#define EXTERNAL_DNS_SERVER "223.5.5.5"// ali
#define FORWARD_TIMEOUT_SEC 2

// DNS报文头结构 (网络字节序)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader;

// DNS 查询问题尾部 (QNAME是变长的)
typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} DNSQuestionTail;


// 域名-IP对照表项（IP在前）
typedef struct {
    char ip[16];
    char domain[256]; // 标准点分域名
} DNSEntry;

// 线程参数结构
typedef struct {
    unsigned char buffer[DNS_BUFFER_SIZE];
    int len;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
} RequestInfo;

// 全局变量
DNSEntry dns_table[MAX_DNS_ENTRIES];
int dns_table_size = 0;
SOCKET_TYPE main_sockfd; // 主监听套接字 (使用 SOCKET_TYPE)

// 函数声明
void load_dns_table(const char* filename);
DNSEntry* find_in_dns_table(const char* domain_str);
int extract_domain_from_query(const unsigned char* dns_msg, int msg_len, char* domain_out, int domain_out_max_len, int* qname_len_in_msg);
void send_error_response(uint16_t original_id, const unsigned char* original_qname, int original_qname_len,
                         struct sockaddr_in* client_addr, socklen_t client_addr_len);
void send_local_a_response(uint16_t original_id, const unsigned char* original_qname, int original_qname_len,
                           const char* ip_to_send, struct sockaddr_in* client_addr, socklen_t client_addr_len);
void forward_to_external_dns(const unsigned char* request, int len,
                             struct sockaddr_in* client_addr, socklen_t client_addr_len);
void* handle_request(void* arg);


// inet_pton for Windows if not available in older MinGW/MSVC (ws2tcpip.h should have it for recent ones)
#if defined(_WIN32) && !defined(HAVE_INET_PTON)
int inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    int size = sizeof(ss);
    char src_copy[INET6_ADDRSTRLEN + 1];

    ZeroMemory(&ss, sizeof(ss));
    strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
    src_copy[INET6_ADDRSTRLEN] = 0;

    if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
        switch (af) {
            case AF_INET:
                *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
                return 1;
            case AF_INET6:
                *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
                return 1;
        }
    }
    return 0;
}
#define HAVE_INET_PTON // To avoid redefinition if ws2tcpip.h has it
#endif

// inet_ntoa is available in winsock.h / winsock2.h but let's be explicit for usage.
// No need for custom inet_ntoa, it's standard in Winsock.

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", GET_LAST_ERROR);
        return 1;
    }
#endif

    load_dns_table("dnsrelay.txt");
    srand(time(NULL));

    main_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
    if(main_sockfd == INVALID_SOCKET) { // Windows uses INVALID_SOCKET
#else
        if(main_sockfd < 0) {
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
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(53);

#ifdef _WIN32
    if(bind(main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR) { // Windows uses SOCKET_ERROR
#else

        if(bind(main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
#endif
        // ***** 关键修改在这里 *****
        printf("bind failed! Winsock Error Code: %d\n", WSAGetLastError()); // Windows uses WSAGetLastError()
        perror("bind failed (ensure you have admin privileges for port 53)");
        CLOSE_SOCKET(main_sockfd);
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
            continue;
        }
        info->client_addr_len = sizeof(info->client_addr);

        info->len = recvfrom(main_sockfd, (char*)info->buffer, DNS_BUFFER_SIZE, 0, // Cast buffer to char* for Windows
                             (struct sockaddr*)&(info->client_addr), &(info->client_addr_len));
#ifdef _WIN32
        if(info->len == SOCKET_ERROR) {
#else
            if(info->len < 0) {
#endif
            perror("recvfrom failed");
            free(info);
            continue;
        }
        if (info->len < sizeof(DNSHeader)) {
            fprintf(stderr, "Received packet too small for DNS header.\n");
            free(info);
            continue;
        }

        pthread_t thread;
        if(pthread_create(&thread, NULL, handle_request, info) != 0) {
            perror("Failed to create thread");
            free(info);
        } else {
            pthread_detach(thread);
        }
    }

    CLOSE_SOCKET(main_sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

void load_dns_table(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if(!fp) {
        printf("Warning: DNS table file '%s' not found or cannot be opened. Starting with an empty table.\n", filename);
        return;
    }

    char line[512];
    while(fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if(line[0] == '#' || line[0] == '\0' || isspace(line[0])) continue;

        char ip_str[16], domain_str[256];
        if(sscanf(line, "%15s %255s", ip_str, domain_str) == 2) {
            if(dns_table_size < MAX_DNS_ENTRIES) {
                strncpy(dns_table[dns_table_size].ip, ip_str, sizeof(dns_table[dns_table_size].ip)-1);
                dns_table[dns_table_size].ip[sizeof(dns_table[dns_table_size].ip)-1] = '\0';
                strncpy(dns_table[dns_table_size].domain, domain_str, sizeof(dns_table[dns_table_size].domain)-1);
                dns_table[dns_table_size].domain[sizeof(dns_table[dns_table_size].domain)-1] = '\0';
                printf("Loaded from file: IP=%s, Domain=%s\n", dns_table[dns_table_size].ip, dns_table[dns_table_size].domain);
                dns_table_size++;
            } else {
                fprintf(stderr, "DNS table full, cannot load more entries.\n");
                break;
            }
        } else {
            fprintf(stderr, "Warning: Malformed line in %s: %s\n", filename, line);
        }
    }
    fclose(fp);
}

DNSEntry* find_in_dns_table(const char* domain_str) {
    for(int i = 0; i < dns_table_size; i++) {
        if(strcmp(dns_table[i].domain, domain_str) == 0) {
            return &dns_table[i];
        }
    }
    return NULL;
}

int extract_domain_from_query(const unsigned char* dns_msg, int msg_len,
                              char* domain_out, int domain_out_max_len,
                              int* qname_len_in_msg) {
    if (msg_len < sizeof(DNSHeader) + 1) return -1;

    int current_offset = sizeof(DNSHeader);
    int name_pos = 0;
    int original_qname_start = current_offset;
    int jumped = 0;
    int jumps_count = 0;

    while (current_offset < msg_len && dns_msg[current_offset] != 0) {
        if (name_pos >= domain_out_max_len - 1) return -1;

        if ((dns_msg[current_offset] & 0xC0) == 0xC0) {
            if (current_offset + 1 >= msg_len) return -1;
            if (jumps_count++ > 10) return -1;

            int ptr_offset = ((dns_msg[current_offset] & 0x3F) << 8) | dns_msg[current_offset + 1];
            if (ptr_offset >= msg_len) return -1;

            if (!jumped) {
                *qname_len_in_msg = (current_offset + 2) - original_qname_start;
                jumped = 1;
            }
            current_offset = ptr_offset;
            continue;
        }

        unsigned char label_len = dns_msg[current_offset];
        if (label_len == 0 || label_len > 63 || current_offset + 1 + label_len > msg_len) { // check bounds
            return -1;
        }
        current_offset++;

        if (name_pos > 0) {
            if (name_pos < domain_out_max_len - 1) domain_out[name_pos++] = '.';
            else return -1;
        }

        if (name_pos + label_len >= domain_out_max_len) return -1;
        memcpy(domain_out + name_pos, dns_msg + current_offset, label_len);
        name_pos += label_len;
        current_offset += label_len;
    }

    if (current_offset >= msg_len || dns_msg[current_offset] != 0) {
        return -1;
    }

    domain_out[name_pos] = '\0';

    if (!jumped) {
        *qname_len_in_msg = (current_offset + 1) - original_qname_start;
    } else if (*qname_len_in_msg == 0 && jumped) {
        *qname_len_in_msg = 2;
    }
    // No need to check for QTYPE/QCLASS space here, just parse QNAME

    return 0;
}

void send_error_response(uint16_t original_id, const unsigned char* original_qname_dns_format, int original_qname_len,
                         struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8183);
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = 0;
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    memcpy(response_buffer + current_pos, original_qname_dns_format, original_qname_len);
    current_pos += original_qname_len;

    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);
    q_tail->qclass = htons(1);
    current_pos += sizeof(DNSQuestionTail);

    sendto(main_sockfd, (char*)response_buffer, current_pos, 0, (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent NXDOMAIN response for ID %u to %s:%d\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}

void send_local_a_response(uint16_t original_id, const unsigned char* original_qname_dns_format, int original_qname_len,
                           const char* ip_to_send_str, struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8180);
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = htons(1);
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    memcpy(response_buffer + current_pos, original_qname_dns_format, original_qname_len);
    current_pos += original_qname_len;

    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);
    q_tail->qclass = htons(1);
    current_pos += sizeof(DNSQuestionTail);

    response_buffer[current_pos++] = 0xC0;
    response_buffer[current_pos++] = 0x0C;

    uint16_t* type_ptr = (uint16_t*)(response_buffer + current_pos);
    *type_ptr = htons(1); current_pos += 2;
    uint16_t* class_ptr = (uint16_t*)(response_buffer + current_pos);
    *class_ptr = htons(1); current_pos += 2;
    uint32_t* ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ttl_ptr = htonl(60); current_pos += 4;
    uint16_t* rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *rdlen_ptr = htons(4); current_pos += 2;

    struct in_addr ip_addr_bin;
    if (inet_pton(AF_INET, ip_to_send_str, &ip_addr_bin) <= 0) { // inet_pton returns 1 on success
        fprintf(stderr, "inet_pton failed for local response IP: %s. Error: %d\n", ip_to_send_str, GET_LAST_ERROR);
        return;
    }
    memcpy(response_buffer + current_pos, &ip_addr_bin.s_addr, 4);
    current_pos += 4;

    sendto(main_sockfd, (char*)response_buffer, current_pos, 0, (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent local A record response (IP: %s) for ID %u to %s:%d\n", ip_to_send_str, ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}

void forward_to_external_dns(const unsigned char* request_data, int request_len,
                             struct sockaddr_in* original_client_addr, socklen_t original_client_addr_len) {
    SOCKET_TYPE forward_sockfd; // Use SOCKET_TYPE
    struct sockaddr_in ext_dns_addr;
    unsigned char response_buffer[DNS_BUFFER_SIZE];

    forward_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
    if (forward_sockfd == INVALID_SOCKET) {
#else
        if (forward_sockfd < 0) {
#endif
        perror("Failed to create forward socket");
        return;
    }

#ifdef _WIN32
    DWORD timeout_ms = FORWARD_TIMEOUT_SEC * 1000;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed (Windows)");
    }
#else
    struct timeval tv;
    tv.tv_sec = FORWARD_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("setsockopt SO_RCVTIMEO failed (POSIX)");
    }
#endif

    memset(&ext_dns_addr, 0, sizeof(ext_dns_addr));
    ext_dns_addr.sin_family = AF_INET;
    ext_dns_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, EXTERNAL_DNS_SERVER, &ext_dns_addr.sin_addr) <= 0) { // inet_pton returns 1 on success
        fprintf(stderr, "inet_pton for external DNS server failed. Error: %d\n", GET_LAST_ERROR);
        CLOSE_SOCKET(forward_sockfd);
        return;
    }

    if (sendto(forward_sockfd, (char*)request_data, request_len, 0, // Cast for Windows
               (struct sockaddr*)&ext_dns_addr, sizeof(ext_dns_addr)) < 0) { // SOCKET_ERROR on Windows
        perror("sendto to external DNS failed");
        CLOSE_SOCKET(forward_sockfd);
        return;
    }
    printf("Forwarded query (ID: %u, len: %d) to %s\n", ntohs(((DNSHeader*)request_data)->id), request_len, EXTERNAL_DNS_SERVER);

    struct sockaddr_in source_addr;
    socklen_t source_addr_len = sizeof(source_addr);
    int response_len = recvfrom(forward_sockfd, (char*)response_buffer, DNS_BUFFER_SIZE, 0, // Cast for Windows
                                (struct sockaddr*)&source_addr, &source_addr_len);

    CLOSE_SOCKET(forward_sockfd);

#ifdef _WIN32
    if (response_len == SOCKET_ERROR) {
        int error_code = GET_LAST_ERROR;
        if (error_code == WSAETIMEDOUT) {
            printf("Timeout receiving from external DNS server.\n");
        } else {
            printf("recvfrom from external DNS failed: %d\n", error_code);
        }
        return;
    }
#else
    if (response_len < 0) {
        perror("recvfrom from external DNS failed (or timeout)");
        return;
    }
#endif


    if (response_len < sizeof(DNSHeader)) {
        fprintf(stderr, "External DNS response too small.\n");
        return;
    }

    DNSHeader* req_hdr = (DNSHeader*)request_data;
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    if (res_hdr->id == req_hdr->id) {
        if (sendto(main_sockfd, (char*)response_buffer, response_len, 0, // Cast for Windows
                   (struct sockaddr*)original_client_addr, original_client_addr_len) < 0) { // SOCKET_ERROR for Windows
            perror("sendto to original client failed");
        } else {
            printf("Forwarded external response (ID: %u, len: %d) to client %s:%d\n",
                   ntohs(res_hdr->id), response_len,
                   inet_ntoa(original_client_addr->sin_addr), ntohs(original_client_addr->sin_port));
        }
    } else {
        fprintf(stderr, "ID mismatch from external DNS. Expected %u, Got %u. Discarding.\n",
                ntohs(req_hdr->id), ntohs(res_hdr->id));
    }
}

void* handle_request(void* arg) {
    RequestInfo* info = (RequestInfo*)arg;
    char queried_domain_str[256];
    int qname_len_in_msg;

    DNSHeader* query_hdr = (DNSHeader*)(info->buffer);
    uint16_t original_id = query_hdr->id;

    if (!((ntohs(query_hdr->flags) & 0x8000) == 0 &&
          ( (ntohs(query_hdr->flags) >> 11) & 0xF ) == 0 &&
          ntohs(query_hdr->qdcount) == 1) ) {
        fprintf(stderr, "Dropping non-standard query or query with multiple questions (ID: %u, Flags: 0x%04X, QDCount: %u).\n",
                ntohs(original_id), ntohs(query_hdr->flags), ntohs(query_hdr->qdcount));
        free(info);
        return NULL;
    }

    const unsigned char* original_qname_dns_format_ptr = info->buffer + sizeof(DNSHeader);

    if (extract_domain_from_query(info->buffer, info->len, queried_domain_str, sizeof(queried_domain_str), &qname_len_in_msg) != 0) {
        fprintf(stderr, "Failed to extract domain from query (ID: %u).\n", ntohs(original_id));
        free(info);
        return NULL;
    }
    printf("Thread %lu: Received query for domain: %s (ID: %u) from %s:%d\n",
           (unsigned long)pthread_self(), queried_domain_str, ntohs(original_id),
           inet_ntoa(info->client_addr.sin_addr), ntohs(info->client_addr.sin_port));

    DNSEntry* local_entry = find_in_dns_table(queried_domain_str);
    if (local_entry != NULL) {
        if (strcmp(local_entry->ip, "0.0.0.0") == 0) {
            printf("Thread %lu: Intercepting %s (ID: %u), sending NXDOMAIN.\n", (unsigned long)pthread_self(), queried_domain_str, ntohs(original_id));
            send_error_response(original_id, original_qname_dns_format_ptr, qname_len_in_msg,
                                &(info->client_addr), info->client_addr_len);
        } else {
            printf("Thread %lu: Locally resolving %s to %s (ID: %u).\n", (unsigned long)pthread_self(), queried_domain_str, local_entry->ip, ntohs(original_id));
            send_local_a_response(original_id, original_qname_dns_format_ptr, qname_len_in_msg,
                                  local_entry->ip, &(info->client_addr), info->client_addr_len);
        }
    } else {
        printf("Thread %lu: Domain %s not found locally (ID: %u), forwarding...\n", (unsigned long)pthread_self(), queried_domain_str, ntohs(original_id));
        forward_to_external_dns(info->buffer, info->len, &(info->client_addr), info->client_addr_len);
    }

    free(info);
    return NULL;
}