#ifndef FORWARDER_H
#define FORWARDER_H

#include "common.h"
#include "dns_protocol.h" // For DNSHeader and send_servfail_response

void forward_to_external_dns(SOCKET_TYPE main_sockfd,
                             const unsigned char* request, int len,
                             const struct sockaddr_in* client_addr, socklen_t client_addr_len,
                             int qname_len_for_servfail,
                             char* upstream_server_info); // qname_len for servfail if needed

#endif // FORWARDER_H