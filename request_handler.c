//request_handler.c
#include "request_handler.h"
#include "dns_protocol.h"
#include "dns_cache.h"
#include "forwarder.h"

void* handle_request(void* arg) {
    RequestInfo* info = (RequestInfo*)arg;
    if (!info) return NULL;

    const unsigned char* qname_start_in_req = info->buffer + sizeof(DNSHeader); // DNS查询名在请求中的起始位置

    DNSHeader* req_hdr = (DNSHeader*)info->buffer; // DNS头部指针
    uint16_t id = req_hdr->id; // 请求ID
    uint16_t flags_host = ntohs(req_hdr->flags); // 标志字段（主机字节序）

    if ((flags_host & 0x8000) != 0) {
        printf("Received response packet (QR=1), ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }
    if (((flags_host >> 11) & 0xF) != 0) {
        printf("Received non-standard query (Opcode != 0), ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }
    if (ntohs(req_hdr->qdcount) != 1) {
        printf("Received query with question count not equal to 1 (qdcount != 1), ignoring. ID: %u\n", ntohs(id));
        free(info);
        return NULL;
    }

    char domain_str[256]; // 域名字符串缓冲区
    int qname_len_in_msg = 0; // 查询名长度
    int extract_result = extract_domain_from_query(
            info->buffer, info->len,
            domain_str, sizeof(domain_str),
            &qname_len_in_msg
    );

    if (extract_result != 0) {
        fprintf(stderr, "Failed to extract domain from query. ID: %u. Packet may be malformed.\n", ntohs(id));
        free(info);
        return NULL;
    }

    if ((int)(sizeof(DNSHeader) + qname_len_in_msg + sizeof(DNSQuestionTail)) > info->len) {
        fprintf(stderr, "Packet too short for QTYPE/QCLASS after QNAME. ID: %u, Domain: %s\n", ntohs(id), domain_str);
        free(info);
        return NULL;
    }

    const DNSQuestionTail* q_tail = (const DNSQuestionTail*)(info->buffer + sizeof(DNSHeader) + qname_len_in_msg); // 查询问题尾部指针
    uint16_t qtype = ntohs(q_tail->qtype); // 查询类型
    uint16_t qclass = ntohs(q_tail->qclass); // 查询类

    if (qclass != 1) {
        printf("Received query with QCLASS != IN (1), ignoring. ID: %u, QCLASS: %u\n", ntohs(id), qclass);
        free(info);
        return NULL;
    }

    DNSEntry* entry = NULL; // DNS表项指针
    if (qtype == 1) {
        entry = find_in_dns_table(domain_str, A_RECORD); // 查找A记录
    } else if (qtype == 12) {
        entry = find_in_dns_table(domain_str, PTR_RECORD); // 查找PTR记录
    } else if (qtype == 28) {
        entry = find_in_dns_table(domain_str, A_RECORD); // 查找AAAA记录对应的A记录
    }


    if(qtype == 12) { // 处理PTR查询
        printf("Processing PTR query for: %s (ID: %u)\n", domain_str, ntohs(id));
        if(entry) {
            printf("Found PTR record in local table: %s -> %s\n", entry->domain, entry->ip);
            send_ptr_response(info->server_sockfd, id,
                              qname_start_in_req, qname_len_in_msg,
                              entry->ip,
                              &info->client_addr, info->client_addr_len);
        } else {
            printf("No local PTR record for: %s, forwarding. (ID: %u)\n", domain_str, ntohs(id));
            char upstream_server_info[MAX_UPSTREAM_INFO_LEN] = {0};
            forward_to_external_dns(info->server_sockfd, info->buffer, info->len,
                                    &info->client_addr, info->client_addr_len,
                                    qname_len_in_msg, upstream_server_info);
        }
        free(info);
        return NULL;
    }

    if (qtype == 1 || qtype == 28) { // 处理A或AAAA查询
        printf("Received %s query for domain: %s (ID: %u) from %s:%d\n",
               (qtype == 1 ? "A" : "AAAA"), domain_str, ntohs(id),
               inet_ntoa(info->client_addr.sin_addr), ntohs(info->client_addr.sin_port));

        if (entry) { // 在本地DNS表中找到对应记录
            if (strcmp(entry->ip, "0.0.0.0") == 0) {
                printf("Blocking domain (configured to 0.0.0.0 in A record): %s for %s query\n",
                       domain_str, (qtype == 1 ? "A" : "AAAA"));
                send_error_response(info->server_sockfd, id, qname_start_in_req, qname_len_in_msg,
                                    &info->client_addr, info->client_addr_len);
            } else { // 记录存在且不是0.0.0.0
                if (qtype == 1) { // 返回本地A记录
                    printf("Found in local table: %s -> %s\n", entry->domain, entry->ip);
                    send_local_a_response(info->server_sockfd, id, qname_start_in_req, qname_len_in_msg,
                                          entry->ip,
                                          &info->client_addr, info->client_addr_len);
                } else { // qtype == 28 (AAAA)
                    // 本地存在A记录（非0.0.0.0），但没有AAAA记录，返回NODATA响应
                    printf("Domain %s has local A record, sending NODATA for AAAA query.\n", domain_str);
                    send_nodata_response(info->server_sockfd, id, qname_start_in_req, qname_len_in_msg,
                                         qtype, // 传递原始查询类型 (28)
                                         &info->client_addr, info->client_addr_len);
                }
            }
        } else { // 本地DNS表中未找到记录
            printf("Domain not found locally, forwarding %s query: %s\n",
                   (qtype == 1 ? "A" : "AAAA"), domain_str);
            char upstream_server_info[MAX_UPSTREAM_INFO_LEN] = {0};
            forward_to_external_dns(info->server_sockfd, info->buffer, info->len,
                                    &info->client_addr, info->client_addr_len,
                                    qname_len_in_msg, upstream_server_info);
            if (upstream_server_info[0] != '\0') {
                printf("Forwarded to DNS server: %s\n", upstream_server_info);
            }
        }
        free(info);
        return NULL;
    }

    printf("Received unsupported query type %u for %s (ID: %u), forwarding.\n", qtype, domain_str, ntohs(id));
    char upstream_server_info[MAX_UPSTREAM_INFO_LEN] = {0};
    forward_to_external_dns(info->server_sockfd, info->buffer, info->len,
                            &info->client_addr, info->client_addr_len,
                            qname_len_in_msg, upstream_server_info);

    free(info);
    return NULL;
}
