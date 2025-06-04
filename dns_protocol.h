#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include "common.h"

// DNS报文头部结构(网络字节序)
typedef struct {
    uint16_t id;      // 事务ID
    uint16_t flags;   // 标志字段
    uint16_t qdcount; // 问题记录数
    uint16_t ancount; // 回答记录数
    uint16_t nscount; // 授权记录数
    uint16_t arcount; // 附加记录数
} DNSHeader;

// DNS查询问题尾部(QNAME是变长的)
typedef struct {
    uint16_t qtype;  // 查询类型
    uint16_t qclass; // 查询类
} DNSQuestionTail;

int extract_ptr_query(const char* ip_str, char* reversed_ip, size_t reversed_ip_len);

int extract_domain_from_query(const unsigned char* dns_msg, int msg_len,
                              char* domain_out, int domain_out_max_len,
                              int* qname_len_in_msg);

void send_error_response(SOCKET_TYPE sockfd, uint16_t original_id,
                         const unsigned char* original_qname_start_ptr, int original_qname_len,
                         const struct sockaddr_in* client_addr, socklen_t client_addr_len);

void send_servfail_response(SOCKET_TYPE sockfd, uint16_t original_id,
                            const unsigned char* original_qname_start_ptr, int original_qname_len,
                            const struct sockaddr_in* client_addr, socklen_t client_addr_len);

void send_local_a_response(SOCKET_TYPE sockfd, uint16_t original_id,
                           const unsigned char* original_qname_start_ptr, int original_qname_len,
                           const char* ip_to_send_str,
                           const struct sockaddr_in* client_addr, socklen_t client_addr_len);

#endif // DNS_PROTOCOL_H