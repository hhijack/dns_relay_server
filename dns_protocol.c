#include "dns_protocol.h"

int extract_domain_from_query(const unsigned char* dns_msg, int msg_len,
                              char* domain_out, int domain_out_max_len,
                              int* qname_len_in_msg) {
    if (msg_len < (int)(sizeof(DNSHeader) + 1)) return -1; // Need at least one byte for QNAME (even if it's just the null terminator)

    int current_offset = sizeof(DNSHeader);
    int name_pos = 0;
    int original_qname_start = current_offset; // Start of QNAME in the message
    int jumped = 0; // Flag to indicate if a jump (compression) has occurred
    int jumps_count = 0; // To prevent infinite loops from malformed packets

    while (current_offset < msg_len && dns_msg[current_offset] != 0) {
        if (name_pos >= domain_out_max_len - 1) return -1; // Output buffer too small

        // Check for compression pointer
        if ((dns_msg[current_offset] & 0xC0) == 0xC0) {
            if (current_offset + 1 >= msg_len) return -1; // Incomplete pointer
            if (jumps_count++ > 10) return -1; // Too many jumps, likely a loop

            int ptr_offset = ((dns_msg[current_offset] & 0x3F) << 8) | dns_msg[current_offset + 1];
            if (ptr_offset >= msg_len) return -1; // Pointer out of bounds

            if (!jumped) { // This is the first jump
                *qname_len_in_msg = (current_offset + 2) - original_qname_start; // Length of QNAME up to and including the pointer
                jumped = 1;
            }
            current_offset = ptr_offset; // Jump to the new offset
            continue; // Continue parsing from the jumped location
        }

        // Not a pointer, so it's a label length
        unsigned char label_len = dns_msg[current_offset];
        if (label_len == 0 || label_len > 63 || current_offset + 1 + label_len > msg_len) {
            // Invalid label length or label extends beyond message
            return -1;
        }
        current_offset++; // Move past the length byte

        if (name_pos > 0) { // Add a dot before the next label if not the first label
            if (name_pos < domain_out_max_len - 1) domain_out[name_pos++] = '.';
            else return -1; // Output buffer too small
        }

        if (name_pos + label_len >= domain_out_max_len) return -1; // Output buffer too small
        memcpy(domain_out + name_pos, dns_msg + current_offset, label_len);
        name_pos += label_len;
        current_offset += label_len;
    }

    if (current_offset >= msg_len || dns_msg[current_offset] != 0) {
        // Should end with a null byte for the root label, or current_offset is out of bounds
        return -1;
    }

    domain_out[name_pos] = '\0'; // Null-terminate the domain string

    if (!jumped) {
        // If no jump occurred, QNAME length is from its start to the null terminator (inclusive)
        *qname_len_in_msg = (current_offset + 1) - original_qname_start;
    } else if (*qname_len_in_msg == 0 && jumped) { // This case should ideally not happen if logic is correct
        // This implies the QNAME was *only* a pointer right after the header.
        // The original code might have implicitly handled this by qname_len_in_msg being set before.
        // For safety, if jumped and qname_len_in_msg is still 0, it means the qname was just a pointer.
        // The length of the pointer itself is 2 bytes.
        *qname_len_in_msg = 2;
    }
    // If current_offset + sizeof(DNSQuestionTail) > msg_len, it's also an error, but that's checked by caller usually.
    return 0; // Success
}

void send_error_response(SOCKET_TYPE sockfd, uint16_t original_id,
                         const unsigned char* original_qname_start_ptr, int original_qname_len,
                         const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;      // Use original ID (already in network byte order)
    res_hdr->flags = htons(0x8183); // Response, RA, RCODE=3 (NXDOMAIN)
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

    sendto(sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent NXDOMAIN response for ID %u to %s:%d\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}

void send_servfail_response(SOCKET_TYPE sockfd, uint16_t original_id,
                            const unsigned char* original_qname_start_ptr, int original_qname_len,
                            const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8182); // Response, RA, RCODE=2 (SERVFAIL)
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

    sendto(sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent SERVFAIL response for ID %u to %s:%d\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}

void send_local_a_response(SOCKET_TYPE sockfd, uint16_t original_id,
                           const unsigned char* original_qname_start_ptr, int original_qname_len,
                           const char* ip_to_send_str,
                           const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8180); // Response, RA, No Error (RCODE=0)
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = htons(1);
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    // Copy QNAME
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    // Copy QTYPE, QCLASS
    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);  // A
    q_tail->qclass = htons(1); // IN
    current_pos += sizeof(DNSQuestionTail);

    // Answer Record
    // NAME (pointer to QNAME)
    response_buffer[current_pos++] = 0xC0; // Compression pointer
    response_buffer[current_pos++] = 0x0C; // Points to QNAME at offset 12 (sizeof(DNSHeader))

    // TYPE, CLASS, TTL, RDLENGTH, RDATA
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
        // Fallback to SERVFAIL if IP conversion fails
        send_servfail_response(sockfd, original_id, original_qname_start_ptr, original_qname_len, client_addr, client_addr_len);
        return;
    }
    memcpy(response_buffer + current_pos, &ip_addr_bin.s_addr, 4);
    current_pos += 4;

    sendto(sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent local A response for ID %u to %s:%d (IP=%s)\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), ip_to_send_str);
}

int extract_ptr_query(const char* ip_str, char* reversed_ip, size_t reversed_ip_len) {
    // Check if ip_str is in format "X.X.X.X"
    int octets[4];
    if (sscanf(ip_str, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) != 4) {
        return -1; // Invalid IP format
    }
    
    // Check if octets are valid (0-255)
    for (int i = 0; i < 4; i++) {
        if (octets[i] < 0 || octets[i] > 255) {
            return -1;
        }
    }
    
    // Build PTR domain name (e.g. "1.0.0.127.in-addr.arpa")
    size_t needed_size = (size_t)snprintf(NULL, 0, "%d.%d.%d.%d.in-addr.arpa", 
                             octets[0], octets[1], octets[2], octets[3]) + 1;
    if (needed_size > reversed_ip_len) {
        return -1; // Buffer too small
    }
    
    snprintf(reversed_ip, reversed_ip_len, "%d.%d.%d.%d.in-addr.arpa", 
            octets[0], octets[1], octets[2], octets[3]);
    return 0;
}

void set_upstream_server_info(unsigned char* response, int response_len, const char* upstream_server) {
    if (!response || !upstream_server || response_len < sizeof(DNSHeader)) {
        return;
    }

    DNSHeader* header = (DNSHeader*)response;
    
    // 确保有足够的空间添加额外信息
    if (response_len + strlen(upstream_server) + 1 > DNS_BUFFER_SIZE) {
        return;
    }

    // 在响应末尾添加上游服务器信息
    strcpy((char*)response + response_len, upstream_server);
    
    // 更新响应长度
    response_len += strlen(upstream_server) + 1;
    
    // 可以在这里添加其他处理逻辑，如设置特定的标志位等
    printf("Added upstream server info: %s\n", upstream_server);
}

void send_ptr_response(SOCKET_TYPE sockfd, uint16_t original_id,
                      const unsigned char* original_qname_start_ptr, int original_qname_len,
                      const char* domain_to_send,
                      const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    (void)original_qname_start_ptr; // Mark as unused
    (void)original_qname_len;      // Mark as unused
    
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;
    
    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8180); // Response, RA, No Error
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = htons(1);
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    // Copy QNAME
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    // Copy QTYPE, QCLASS
    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(12);  // PTR
    q_tail->qclass = htons(1);  // IN
    current_pos += sizeof(DNSQuestionTail);

    // Answer Record
    // NAME (pointer to QNAME)
    response_buffer[current_pos++] = 0xC0; // Compression pointer
    response_buffer[current_pos++] = 0x0C; // Points to QNAME at offset 12 (sizeof(DNSHeader))

    // TYPE, CLASS, TTL, RDLENGTH, RDATA
    uint16_t* type_ptr = (uint16_t*)(response_buffer + current_pos);
    *type_ptr = htons(12); current_pos += 2; // TYPE = PTR (12)
    uint16_t* class_ptr = (uint16_t*)(response_buffer + current_pos);
    *class_ptr = htons(1); current_pos += 2; // CLASS = IN (1)
    uint32_t* ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ttl_ptr = htonl(60); current_pos += 4;  // TTL = 60 seconds
    
    // Calculate domain length
    int domain_len = strlen(domain_to_send) + 1; // +1 for null terminator
    uint16_t* rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *rdlen_ptr = htons(domain_len); current_pos += 2; // RDLENGTH
    
    // Copy domain name
    memcpy(response_buffer + current_pos, domain_to_send, domain_len);
    current_pos += domain_len;

    sendto(sockfd, (char*)response_buffer, current_pos, 0,
          (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent PTR response for ID %u to %s:%d (Domain=%s)\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), domain_to_send);
}
