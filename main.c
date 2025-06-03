#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> // For InetPton, inet_ntoa
#include <windows.h>  // For Sleep
#pragma comment(lib, "ws2_32.lib") // Link with ws2_32.lib
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET closesocket
#define GET_LAST_ERROR WSAGetLastError()
#include <pthread.h> // Assuming pthreads-win32 or MinGW's winpthreads
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
#define EXTERNAL_DNS_SERVER "223.5.5.5" // 阿里公共DNS
#define FORWARD_TIMEOUT_SEC 2           // 单次查询超时时间
#define MAX_RETRIES 2                   // 最大重试次数

// DNS报文头结构 (网络字节序)
typedef struct {
    uint16_t id;      // 事务ID
    uint16_t flags;   // 标志字段
    uint16_t qdcount; // 问题计数
    uint16_t ancount; // 回答计数
    uint16_t nscount; // 授权记录计数
    uint16_t arcount; // 附加记录计数
} DNSHeader;

// DNS 查询问题尾部 (QNAME是变长的)
typedef struct {
    uint16_t qtype;  // 查询类型
    uint16_t qclass; // 查询类
} DNSQuestionTail;

// 域名-IP对照表项（IP在前）
typedef struct {
    char ip[16];      // IP地址
    char domain[256]; // 标准点分域名
} DNSEntry;

// 线程参数结构
typedef struct {
    unsigned char buffer[DNS_BUFFER_SIZE]; // 接收缓冲区
    int len;                               // 数据长度
    struct sockaddr_in client_addr;        // 客户端地址
    socklen_t client_addr_len;             // 地址长度
} RequestInfo;

// 全局变量
DNSEntry dns_table[MAX_DNS_ENTRIES]; // DNS表
int dns_table_size = 0;              // DNS表大小
SOCKET_TYPE main_sockfd;             // 主监听套接字

// 函数声明
void load_dns_table(const char* filename);
DNSEntry* find_in_dns_table(const char* domain_str);
int extract_domain_from_query(const unsigned char* dns_msg, int msg_len, char* domain_out, int domain_out_max_len, int* qname_len_in_msg);
void send_error_response(uint16_t original_id, const unsigned char* original_qname_start_ptr, int original_qname_len,
                         struct sockaddr_in* client_addr, socklen_t client_addr_len);
void send_local_a_response(uint16_t original_id, const unsigned char* original_qname_start_ptr, int original_qname_len,
                           const char* ip_to_send, struct sockaddr_in* client_addr, socklen_t client_addr_len);
void send_servfail_response(uint16_t original_id, const unsigned char* original_qname_start_ptr, int original_qname_len,
                            struct sockaddr_in* client_addr, socklen_t client_addr_len);
void forward_to_external_dns(const unsigned char* request, int len,
                             struct sockaddr_in* client_addr, socklen_t client_addr_len,
                             int qname_len_for_servfail); // qname_len for servfail if needed
void* handle_request(void* arg);



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
    if(main_sockfd == INVALID_SOCKET) {
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
    if(bind(main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR) {
#else
        if(bind(main_sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
#endif
        printf("bind failed! Error Code: %d\n", GET_LAST_ERROR);
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
            continue; // Avoid exiting the server for one failed allocation
        }
        info->client_addr_len = sizeof(info->client_addr);

        info->len = recvfrom(main_sockfd, (char*)info->buffer, DNS_BUFFER_SIZE, 0,
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
            free(info); // Free memory if thread creation fails
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
        if (label_len == 0 || label_len > 63 || current_offset + 1 + label_len > msg_len) {
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
    } else if (*qname_len_in_msg == 0 && jumped) { // Should have been set if only jump
        *qname_len_in_msg = 2; // Length of the pointer itself
    }
    return 0;
}

void send_error_response(uint16_t original_id, const unsigned char* original_qname_start_ptr, int original_qname_len,
                         struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8183); // NXDOMAIN
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = 0;
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);  // A
    q_tail->qclass = htons(1); // IN
    current_pos += sizeof(DNSQuestionTail);

    sendto(main_sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent NXDOMAIN response for ID %u to %s:%d\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}

void send_servfail_response(uint16_t original_id, const unsigned char* original_qname_start_ptr, int original_qname_len,
                            struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8182); // SERVFAIL (RCODE=2)
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = 0;
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);  // A
    q_tail->qclass = htons(1); // IN
    current_pos += sizeof(DNSQuestionTail);

    sendto(main_sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent SERVFAIL response for ID %u to %s:%d\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}

void send_local_a_response(uint16_t original_id, const unsigned char* original_qname_start_ptr, int original_qname_len,
                           const char* ip_to_send_str, struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8180); // No Error, Authoritative Answer (can be set)
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = htons(1);
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);  // A
    q_tail->qclass = htons(1); // IN
    current_pos += sizeof(DNSQuestionTail);

    // Answer Record
    response_buffer[current_pos++] = 0xC0; // Compression pointer
    response_buffer[current_pos++] = 0x0C; // Points to QNAME at offset 12 (after header)

    uint16_t* type_ptr = (uint16_t*)(response_buffer + current_pos);
    *type_ptr = htons(1); current_pos += 2; // TYPE = A (1)
    uint16_t* class_ptr = (uint16_t*)(response_buffer + current_pos);
    *class_ptr = htons(1); current_pos += 2; // CLASS = IN (1)
    uint32_t* ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ttl_ptr = htonl(60); current_pos += 4;  // TTL = 60 seconds
    uint16_t* rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *rdlen_ptr = htons(4); current_pos += 2; // RDLENGTH = 4 for IPv4

    struct in_addr ip_addr_bin;
    if (inet_pton(AF_INET, ip_to_send_str, &ip_addr_bin) <= 0) {
        fprintf(stderr, "inet_pton failed for local response IP: %s. Error: %d\n", ip_to_send_str, GET_LAST_ERROR);
        send_servfail_response(original_id, original_qname_start_ptr, original_qname_len, client_addr, client_addr_len);
        return;
    }
    memcpy(response_buffer + current_pos, &ip_addr_bin.s_addr, 4);
    current_pos += 4;

    sendto(main_sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent local A response for ID %u to %s:%d (IP=%s)\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), ip_to_send_str);
}

void* handle_request(void* arg) {
    RequestInfo* info = (RequestInfo*)arg;
    if (!info) return NULL;

    DNSHeader* req_hdr = (DNSHeader*)info->buffer;
    uint16_t id = req_hdr->id; // Network byte order, use as is for responses
    uint16_t flags_host = ntohs(req_hdr->flags); // Host byte order for checks

    if ((flags_host & 0x8000) != 0) { // QR bit (0 for query, 1 for response)
        printf("Received packet is a response (QR=1), ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }
    if (((flags_host >> 11) & 0xF) != 0) { // Opcode (0 for standard query)
        printf("Received non-standard query (Opcode != 0), ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }
    if (ntohs(req_hdr->qdcount) != 1) { // Question Count
        printf("Received query with qdcount != 1, ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }

    char domain_str[256];
    int qname_len_in_msg = 0;
    int extract_result = extract_domain_from_query(
            info->buffer, info->len,
            domain_str, sizeof(domain_str),
            &qname_len_in_msg
    );

    if (extract_result != 0) {
        fprintf(stderr, "Failed to extract domain from query. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }

    printf("Received query for domain: %s (ID: %u) from %s:%d\n", domain_str, ntohs(id),
           inet_ntoa(info->client_addr.sin_addr), ntohs(info->client_addr.sin_port));

    DNSEntry* entry = find_in_dns_table(domain_str);
    const unsigned char* qname_start_in_req = info->buffer + sizeof(DNSHeader);

    if (entry) {
        if (strcmp(entry->ip, "0.0.0.0") == 0) {
            printf("Blocking domain: %s\n", domain_str);
            send_error_response(id, qname_start_in_req, qname_len_in_msg,
                                &info->client_addr, info->client_addr_len);
        } else {
            printf("Found in local table: %s -> %s\n", domain_str, entry->ip);
            send_local_a_response(id, qname_start_in_req, qname_len_in_msg,
                                  entry->ip, &info->client_addr, info->client_addr_len);
        }
    } else {
        printf("Domain not found locally, forwarding to external DNS: %s\n", domain_str);
        // For servfail, qname_len is needed if the original qname is to be included in the servfail response's question section
        forward_to_external_dns(info->buffer, info->len,
                                &info->client_addr, info->client_addr_len,
                                qname_len_in_msg);
    }

    free(info);
    return NULL;
}

void forward_to_external_dns(const unsigned char* request, int len,
                             struct sockaddr_in* client_addr, socklen_t client_addr_len,
                             int qname_len_for_servfail) {
    struct sockaddr_in external_dns_addr;
    memset(&external_dns_addr, 0, sizeof(external_dns_addr));
    external_dns_addr.sin_family = AF_INET;
    external_dns_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, EXTERNAL_DNS_SERVER, &external_dns_addr.sin_addr) <= 0) {
        perror("inet_pton failed for external DNS server");
        send_servfail_response(((DNSHeader*)request)->id, request + sizeof(DNSHeader), qname_len_for_servfail,
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
        send_servfail_response(((DNSHeader*)request)->id, request + sizeof(DNSHeader), qname_len_for_servfail,
                               client_addr, client_addr_len);
        return;
    }

#ifdef _WIN32
    DWORD timeout_val = FORWARD_TIMEOUT_SEC * 1000;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_val, sizeof(timeout_val)) < 0) {
        printf("setsockopt SO_RCVTIMEO failed (Windows): %d\n", GET_LAST_ERROR);
    }
#else
    struct timeval tv;
    tv.tv_sec = FORWARD_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(forward_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed (POSIX)");
    }
#endif

    int retries = 0;
    while (retries < MAX_RETRIES) {
        if (sendto(forward_sockfd, (const char*)request, len, 0,
                   (struct sockaddr*)&external_dns_addr, sizeof(external_dns_addr)) < 0) { // SOCKET_ERROR on Windows
            perror("sendto external DNS failed");
            retries++;
#ifdef _WIN32
            Sleep(100);
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
            if (resp_len >= sizeof(DNSHeader) &&
                ((DNSHeader*)response_buffer)->id == ((DNSHeader*)request)->id) {
                if (sendto(main_sockfd, (char*)response_buffer, resp_len, 0,
                           (struct sockaddr*)client_addr, client_addr_len) < 0) { // SOCKET_ERROR on Windows
                    perror("sendto original client failed");
                } else {
                    printf("Forwarded external response for ID %u to %s:%d\n",
                           ntohs(((DNSHeader*)response_buffer)->id),
                           inet_ntoa(client_addr->sin_addr),
                           ntohs(client_addr->sin_port));
                }
                CLOSE_SOCKET(forward_sockfd);
                return;
            } else {
                printf("ID mismatch or invalid response size from external DNS. Retrying...\n");
            }
        } else { // recvfrom failed or timed out
#ifdef _WIN32
            if (GET_LAST_ERROR == WSAETIMEDOUT) {
                printf("Timeout receiving from external DNS. Retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                printf("recvfrom external DNS failed with error: %d. Retrying...\n", GET_LAST_ERROR);
            }
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Timeout receiving from external DNS. Retrying... (%d/%d)\n", retries + 1, MAX_RETRIES);
            } else {
                perror("recvfrom external DNS failed. Retrying...");
            }
#endif
        }
        retries++;
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }

    fprintf(stderr, "All retries failed for external DNS query (ID: %u)\n", ntohs(((DNSHeader*)request)->id));
    send_servfail_response(((DNSHeader*)request)->id, request + sizeof(DNSHeader), qname_len_for_servfail,
                           client_addr, client_addr_len);
    CLOSE_SOCKET(forward_sockfd);
}