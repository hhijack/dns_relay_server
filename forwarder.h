#ifndef FORWARDER_H
#define FORWARDER_H

#include "common.h"
#include "dns_protocol.h" // 用于DNSHeader结构和send_servfail_response函数

void forward_to_external_dns(SOCKET_TYPE main_sockfd,
                             const unsigned char* request, int len,
                             const struct sockaddr_in* client_addr, socklen_t client_addr_len,
                             int qname_len_for_servfail,
                             char* upstream_server_info); // 如果需要servfail响应时的qname长度

#endif // FORWARDER_H