#include "request_handler.h"

// 前置声明
int extract_ptr_query(const char* ip_str, char* reversed_ip, size_t reversed_ip_len);
int send_ptr_response(SOCKET_TYPE sockfd, uint16_t id, 
                     const unsigned char* original_qname_start_ptr, int original_qname_len,
                     const char* domain_to_send, const struct sockaddr_in* client_addr);

#include "dns_protocol.h"
#include "dns_cache.h"
#include "forwarder.h"

void* handle_request(void* arg) {
    RequestInfo* info = (RequestInfo*)arg;
    if (!info) return NULL;

    DNSHeader* req_hdr = (DNSHeader*)info->buffer;
    uint16_t id = req_hdr->id; 
    uint16_t flags_host = ntohs(req_hdr->flags);
    
    // 新增：将qname_start_in_req变量声明移至函数作用域开始处
    const unsigned char* qname_start_in_req = info->buffer + sizeof(DNSHeader);

    // DNS查询基本验证
    if ((flags_host & 0x8000) != 0) { // QR位(0表示查询,1表示响应)
        printf("Received response packet (QR=1), ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }
    if (((flags_host >> 11) & 0xF) != 0) { // Opcode(0表示标准查询)
        // 我们只支持标准查询(Opcode 0)
        printf("Received non-standard query (Opcode != 0), ignoring. ID: %u\n", ntohs(id));
        // 可选发送NOTIMP(未实现,RCODE 4)
        // send_notimp_response(info->server_sockfd, id, ...);
        free(info);
        return NULL;
    }
    if (ntohs(req_hdr->qdcount) != 1) { // 问题数量
        // 我们期望只有一个问题
        printf("Received query with question count not equal to 1 (qdcount != 1), ignoring. ID: %u\n", ntohs(id));
        // 可选发送FORMERR(格式错误,RCODE 1)
        // send_formerr_response(info->server_sockfd, id, ...);
        free(info);
        return NULL;
    }

    char domain_str[256];
    int qname_len_in_msg = 0; // This will store the length of the QNAME in the DNS message
    int extract_result = extract_domain_from_query(
            info->buffer, info->len,
            domain_str, sizeof(domain_str),
            &qname_len_in_msg
    );

    if (extract_result != 0) {
        fprintf(stderr, "Failed to extract domain from query. ID: %u. Packet may be malformed.\n", ntohs(id));
        // 可选发送FORMERR(格式错误,RCODE 1)
        // 目前按照原始行为，在提取失败时不发送响应
        free(info);
        return NULL;
    }

    // 检查QNAME后是否有QTYPE和QCLASS
    if ((int)(sizeof(DNSHeader) + qname_len_in_msg + sizeof(DNSQuestionTail)) > info->len) {
        fprintf(stderr, "Packet too short for QTYPE/QCLASS after QNAME. ID: %u, Domain: %s\n", ntohs(id), domain_str);
        free(info);
        return NULL;
    }

    // 解析查询类型
    const DNSQuestionTail* q_tail = (const DNSQuestionTail*)(info->buffer + sizeof(DNSHeader) + qname_len_in_msg);
    uint16_t qtype = ntohs(q_tail->qtype);
    
    // 处理PTR查询
    if(qtype == 12) { // PTR类型
        printf("Processing PTR query for: %s (ID: %u)\n", domain_str, ntohs(id));
        char reversed_ip[256];
        if(extract_ptr_query(domain_str, reversed_ip, sizeof(reversed_ip)) == 0) {
            printf("Extracted reversed IP: %s\n", reversed_ip);
            DNSEntry* entry = find_in_dns_table(reversed_ip, PTR_RECORD);
            if(entry) {
                printf("Found PTR record: %s -> %s\n", reversed_ip, entry->domain);
                send_ptr_response(info->server_sockfd, id,
                                qname_start_in_req, qname_len_in_msg,
                                entry->domain, &info->client_addr);
                free(info);
                return NULL;
            } else {
                printf("No PTR record found for: %s\n", reversed_ip);
            }
        } else {
            printf("Failed to extract PTR query from: %s\n", domain_str);
        }
    }

    printf("Received query for domain: %s (ID: %u) from %s:%d\n", domain_str, ntohs(id),
           inet_ntoa(info->client_addr.sin_addr), ntohs(info->client_addr.sin_port));

    DNSEntry* entry = find_in_dns_table(domain_str, A_RECORD);

    if (entry) {
        if (strcmp(entry->ip, "0.0.0.0") == 0) {
            printf("Blocking domain: %s\n", domain_str);
            send_error_response(info->server_sockfd, id, qname_start_in_req, qname_len_in_msg,
                                &info->client_addr, info->client_addr_len);
        } else {
            printf("Found in local table: %s -> %s\n", domain_str, entry->ip);
            send_local_a_response(info->server_sockfd, id, qname_start_in_req, qname_len_in_msg,
                                  entry->ip, &info->client_addr, info->client_addr_len);
        }
    } else {
        printf("Domain not found locally, forwarding to external DNS: %s\n", domain_str);
        char upstream_server_info[64] = {0};
        forward_to_external_dns(info->server_sockfd, info->buffer, info->len,
                                &info->client_addr, info->client_addr_len,
                                qname_len_in_msg, upstream_server_info); // Pass qname_len for potential SERVFAIL
    }

    free(info);
    return NULL;
}