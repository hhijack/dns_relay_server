//dns_protocol.c
#include "dns_protocol.h"

int extract_domain_from_query(const unsigned char* dns_msg, int msg_len,
                              char* domain_out, int domain_out_max_len,
                              int* qname_len_in_msg) {
    if (msg_len < (int)(sizeof(DNSHeader) + 1)) return -1; // 至少需要一个字节用于QNAME(即使只是空终止符)

    int current_offset = sizeof(DNSHeader);
    int name_pos = 0;
    int original_qname_start = current_offset; // QNAME在消息中的起始位置
    int jumped = 0; // 标记是否发生了跳转(压缩)
    int jumps_count = 0; // 防止畸形数据包导致的无限循环

    while (current_offset < msg_len && dns_msg[current_offset] != 0) {
        if (name_pos >= domain_out_max_len - 1) return -1; // 输出缓冲区太小

        // 检查压缩指针
        if ((dns_msg[current_offset] & 0xC0) == 0xC0) {
            if (current_offset + 1 >= msg_len) return -1; // 指针不完整
            if (jumps_count++ > 10) return -1; // 跳转次数过多，可能存在循环

            int ptr_offset = ((dns_msg[current_offset] & 0x3F) << 8) | dns_msg[current_offset + 1];
            if (ptr_offset >= msg_len) return -1; // 指针越界

            if (!jumped) { // 这是第一次跳转
                *qname_len_in_msg = (current_offset + 2) - original_qname_start; // QNAME的长度，包括指针
                jumped = 1;
            }
            current_offset = ptr_offset; // 跳转到新偏移量
            continue; // 从跳转位置继续解析
        }

        // 不是指针，所以是标签长度
        unsigned char label_len = dns_msg[current_offset];
        if (label_len == 0 || label_len > 63 || current_offset + 1 + label_len > msg_len) {
            // 无效的标签长度或标签超出消息范围
            return -1;
        }
        current_offset++; // 跳过长度字节

        if (name_pos > 0) { // 如果不是第一个标签，在下一个标签前添加点
            if (name_pos < domain_out_max_len - 1) domain_out[name_pos++] = '.';
            else return -1; // 输出缓冲区太小
        }

        if (name_pos + label_len >= domain_out_max_len) return -1; // 输出缓冲区太小
        memcpy(domain_out + name_pos, dns_msg + current_offset, label_len);
        name_pos += label_len;
        current_offset += label_len;
    }

    if (current_offset >= msg_len || dns_msg[current_offset] != 0) {
        // 应该以空字节结束根标签，或者current_offset越界
        return -1;
    }

    domain_out[name_pos] = '\0'; // 以空字符终止域名字符串

    if (!jumped) {
        // 如果没有发生跳转，QNAME长度是从其开始到空终止符（包括）
        *qname_len_in_msg = (current_offset + 1) - original_qname_start;
    } else if (*qname_len_in_msg == 0 && jumped) { // 如果逻辑正确，这种情况不应该发生
        // 这意味着QNAME在头部之后只是一个指针。
        // 原始代码可能通过qname_len_in_msg在之前设置来隐式处理这种情况。
        // 为了安全起见，如果跳转且qname_len_in_msg仍为0，意味着qname只是一个指针。
        // 指针本身的长度是2字节。
        *qname_len_in_msg = 2;
    }
    // 如果current_offset + sizeof(DNSQuestionTail) > msg_len，也是错误，但通常由调用者检查。
    return 0; // 成功
}

void send_error_response(SOCKET_TYPE sockfd, uint16_t original_id,
                         const unsigned char* original_qname_start_ptr, int original_qname_len,
                         const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;      // 使用原始ID（已经是网络字节序）
    res_hdr->flags = htons(0x8183); // 响应，RA，RCODE=3（NXDOMAIN）
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
    res_hdr->flags = htons(0x8182); // 响应，RA，RCODE=2（SERVFAIL）
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
    res_hdr->flags = htons(0x8580); // 响应，权威，RA，无错误（RCODE=0）
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = htons(1);
    res_hdr->nscount = htons(1);  // 添加一个NS记录
    res_hdr->arcount = 0;

    int current_pos = sizeof(DNSHeader);
    // 复制QNAME
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    // 复制QTYPE, QCLASS
    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(1);  // A
    q_tail->qclass = htons(1); // IN
    current_pos += sizeof(DNSQuestionTail);

    // 应答记录
    // NAME（指向QNAME的指针）
    response_buffer[current_pos++] = 0xC0; // 压缩指针
    response_buffer[current_pos++] = 0x0C; // 指向偏移量12的QNAME（sizeof(DNSHeader)）

    // TYPE, CLASS, TTL, RDLENGTH, RDATA
    uint16_t* type_ptr = (uint16_t*)(response_buffer + current_pos);
    *type_ptr = htons(1); current_pos += 2; // TYPE = A (1)
    uint16_t* class_ptr = (uint16_t*)(response_buffer + current_pos);
    *class_ptr = htons(1); current_pos += 2; // CLASS = IN (1)
    uint32_t* ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ttl_ptr = htonl(60); current_pos += 4;  // TTL = 60秒
    uint16_t* rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *rdlen_ptr = htons(4); current_pos += 2; // RDLENGTH = 4（IPv4）

    struct in_addr ip_addr_bin;
    if (inet_pton(AF_INET, ip_to_send_str, &ip_addr_bin) <= 0) {
        fprintf(stderr, "inet_pton failed for local response IP: %s. Error: %d\n", ip_to_send_str, GET_LAST_ERROR);
        // 如果IP转换失败，回退到SERVFAIL
        send_servfail_response(sockfd, original_id, original_qname_start_ptr, original_qname_len, client_addr, client_addr_len);
        return;
    }
    memcpy(response_buffer + current_pos, &ip_addr_bin.s_addr, 4);
    current_pos += 4;

    // 添加权威服务器部分
    // 1. 添加NS记录
    response_buffer[current_pos++] = 0xC0; // 压缩指针
    response_buffer[current_pos++] = 0x0C; // 指向QNAME

    uint16_t* ns_type_ptr = (uint16_t*)(response_buffer + current_pos);
    *ns_type_ptr = htons(2); current_pos += 2; // TYPE = NS (2)
    uint16_t* ns_class_ptr = (uint16_t*)(response_buffer + current_pos);
    *ns_class_ptr = htons(1); current_pos += 2; // CLASS = IN (1)
    uint32_t* ns_ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ns_ttl_ptr = htonl(60); current_pos += 4;  // TTL = 60秒

    // NS记录数据 - "localhost" (DNS标签格式: \x07localhost\x00)
    unsigned char ns_dname_dns_format[256]; // Buffer for DNS label format
    int ns_dname_encoded_len = 0;
    const char* ns_name_part = "localhost";
    unsigned char len_byte = (unsigned char)strlen(ns_name_part);
    ns_dname_dns_format[ns_dname_encoded_len++] = len_byte;
    strcpy((char*)ns_dname_dns_format + ns_dname_encoded_len, ns_name_part);
    ns_dname_encoded_len += strlen(ns_name_part);
    ns_dname_dns_format[ns_dname_encoded_len++] = 0; // Null terminator for the domain name sequence

    uint16_t* ns_rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *ns_rdlen_ptr = htons(ns_dname_encoded_len); current_pos += 2;
    memcpy(response_buffer + current_pos, ns_dname_dns_format, ns_dname_encoded_len);
    current_pos += ns_dname_encoded_len;

    // 2. 设置DNS头部的权威标志位
    res_hdr->flags = htons(0x8580); // AA=1 (权威应答), RA=1, RCODE=0

    sendto(sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent local A response for ID %u to %s:%d (IP=%s)\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), ip_to_send_str);
}

int extract_ptr_query(const char* ip_str, char* reversed_ip, size_t reversed_ip_len) {
    // 检查ip_str是否为"X.X.X.X"格式
    int octets[4];
    // PTR查询的domain_str通常是 "d.c.b.a.in-addr.arpa"
    // 我们需要从中提取 "a.b.c.d"
    // 或者，如果输入直接是 "a.b.c.d"，我们要把它转换成 "d.c.b.a.in-addr.arpa"
    // 当前函数的意图似乎是后者，即从 "a.b.c.d" 生成 "d.c.b.a.in-addr.arpa"
    // 但在 request_handler.c 中，domain_str 已经是 "d.c.b.a.in-addr.arpa" 格式
    // 所以这个函数在 request_handler.c 中的调用，其输入 ip_str 实际上是 "d.c.b.a.in-addr.arpa"
    // 而 find_in_dns_table 需要的 key 是 "d.c.b.a.in-addr.arpa"
    // 因此，如果输入已经是 "X.X.X.X.in-addr.arpa" 格式，我们应该直接使用它
    // 如果输入是 "X.X.X.X"，我们才需要转换。
    // 为了兼容 request_handler.c 中的用法，如果 ip_str 包含 "in-addr.arpa"，则直接复制。

    if (strstr(ip_str, ".in-addr.arpa") != NULL) {
        // 输入已经是 PTR 域名格式
        if (strlen(ip_str) < reversed_ip_len) {
            strcpy(reversed_ip, ip_str);
            return 0; // 成功
        } else {
            return -1; // 缓冲区太小
        }
    }

    // 否则，假设输入是 "a.b.c.d"，需要转换为 "d.c.b.a.in-addr.arpa"
    if (sscanf(ip_str, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) != 4) {
        return -1; // 无效的IP格式
    }

    // 检查八位组是否有效（0-255）
    for (int i = 0; i < 4; i++) {
        if (octets[i] < 0 || octets[i] > 255) {
            return -1;
        }
    }

    // 构建PTR域名（例如 "d.c.b.a.in-addr.arpa"）
    // 注意：PTR记录的查询名是反转的IP加上.in-addr.arpa后缀
    // 例如，IP 192.168.1.1 对应的PTR查询名是 1.1.168.192.in-addr.arpa
    // 所以，如果输入是 "192.168.1.1"，输出应该是 "1.1.168.192.in-addr.arpa"
    size_t needed_size = (size_t)snprintf(NULL, 0, "%d.%d.%d.%d.in-addr.arpa",
                                          octets[3], octets[2], octets[1], octets[0]) + 1;
    if (needed_size > reversed_ip_len) {
        return -1; // 缓冲区太小
    }

    snprintf(reversed_ip, reversed_ip_len, "%d.%d.%d.%d.in-addr.arpa",
             octets[3], octets[2], octets[1], octets[0]);
    return 0;
}


void set_upstream_server_info(unsigned char* response, int response_len, const char* upstream_server) {
    if (!response || !upstream_server || response_len < (int)sizeof(DNSHeader)) {  // 添加类型转换
        return;
    }

    // 确保有足够的空间添加额外信息
    if (response_len + strlen(upstream_server) + 1 > DNS_BUFFER_SIZE) {
        // 这个操作会破坏DNS包，不应修改response本身
        // printf("Warning: Not enough space in DNS buffer to add upstream server info.\n");
        return;
    }

    // 在响应末尾添加上游服务器信息 - 这个行为会破坏DNS协议，客户端无法解析
    // strcpy((char*)response + response_len, upstream_server);

    // 更新响应长度 - 这个行为会破坏DNS协议
    // response_len += strlen(upstream_server) + 1;

    // 仅打印信息，不修改实际的DNS响应包
    printf("Upstream server for this forwarded response was: %s\n", upstream_server);
}
void send_ptr_response(SOCKET_TYPE sockfd, uint16_t original_id,
                       const unsigned char* original_qname_start_ptr, int original_qname_len,
                       const char* domain_to_send,
                       const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    // (void)original_qname_start_ptr; // 标记为未使用 - 实际会使用该参数
    // (void)original_qname_len;      // 标记为未使用 - 实际会使用该参数

    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    // 设置DNS响应头字段
    res_hdr->id = original_id;
    res_hdr->flags = htons(0x8580); // 响应报文，权威应答，支持递归，无错误
    res_hdr->qdcount = htons(1);    // 问题部分1条记录
    res_hdr->ancount = htons(1);    // 回答部分1条记录
    res_hdr->nscount = htons(1);    // 权威部分1条NS记录 (RFC 1035 4.1.1 头部格式)
    res_hdr->arcount = 0;           // 附加部分0条记录

    int current_pos = sizeof(DNSHeader);
    // 复制查询域名 (例如: 1.0.0.127.in-addr.arpa)
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    // 设置查询类型和查询类
    DNSQuestionTail* q_tail = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail->qtype = htons(12);  // PTR查询类型
    q_tail->qclass = htons(1);  // IN互联网类
    current_pos += sizeof(DNSQuestionTail);

    /* 回答部分 (Answer Section) */
    // 域名指针 (指向查询部分的域名偏移)
    response_buffer[current_pos++] = 0xC0; // 压缩指针标志
    response_buffer[current_pos++] = 0x0C; // 指向偏移量12的QNAME（sizeof(DNSHeader)）

    // 设置资源记录类型、类、TTL和RDATA长度
    uint16_t* type_ptr = (uint16_t*)(response_buffer + current_pos);
    *type_ptr = htons(12); current_pos += 2; // 类型=PTR(12)
    uint16_t* class_ptr = (uint16_t*)(response_buffer + current_pos);
    *class_ptr = htons(1); current_pos += 2; // 类=IN(1)
    uint32_t* ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ttl_ptr = htonl(60); current_pos += 4;  // TTL=60秒

    // RDATA (要返回的域名，如"localhost")
    // 需要将域名转换为DNS标签格式: \x07localhost\x00
    unsigned char domain_dns_format[256]; // DNS标签格式缓冲区
    int domain_encoded_len = 0;
    char* domain_copy = strdup(domain_to_send); // 创建可修改的副本用于strtok
    if (!domain_copy) {
        perror("strdup failed in send_ptr_response");
        // 可选返回SERVFAIL或记录错误
        return;
    }
    // 按点号分割域名并编码为DNS标签格式
    char* token = strtok(domain_copy, ".");
    while(token != NULL) {
        unsigned char len_byte = (unsigned char)strlen(token);
        if (domain_encoded_len + 1 + len_byte >= sizeof(domain_dns_format) -1) { // -1保留结尾空字符
            fprintf(stderr, "Domain name too long for DNS format buffer\n");
            free(domain_copy);
            return; // 或返回SERVFAIL
        }
        domain_dns_format[domain_encoded_len++] = len_byte;
        strcpy((char*)domain_dns_format + domain_encoded_len, token);
        domain_encoded_len += strlen(token);
        token = strtok(NULL, ".");
    }
    domain_dns_format[domain_encoded_len++] = 0; // 域名序列结束符
    free(domain_copy);

    // 设置RDATA长度并复制编码后的域名
    uint16_t* rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *rdlen_ptr = htons(domain_encoded_len); current_pos += 2;
    memcpy(response_buffer + current_pos, domain_dns_format, domain_encoded_len);
    current_pos += domain_encoded_len;

    /* 权威部分 (Authority Section) - NS记录 */
    // 域名指针 (指向查询部分的域名偏移)
    response_buffer[current_pos++] = 0xC0; // 压缩指针
    response_buffer[current_pos++] = 0x0C; // 指向QNAME

    // 设置NS记录类型、类和TTL
    uint16_t* ns_type_ptr = (uint16_t*)(response_buffer + current_pos);
    *ns_type_ptr = htons(2); current_pos += 2; // 类型=NS(2)
    uint16_t* ns_class_ptr = (uint16_t*)(response_buffer + current_pos);
    *ns_class_ptr = htons(1); current_pos += 2; // 类=IN(1)
    uint32_t* ns_ttl_ptr = (uint32_t*)(response_buffer + current_pos);
    *ns_ttl_ptr = htonl(60); current_pos += 4; // TTL=60秒

    // NS记录数据 (NSDNAME) - 如"localhost"的DNS标签格式
    unsigned char ns_dname_dns_format[256];
    int ns_dname_encoded_len = 0;
    const char* ns_name_part = "localhost"; // 或可配置的该区域NS服务器名
    unsigned char len_byte_ns = (unsigned char)strlen(ns_name_part);
    ns_dname_dns_format[ns_dname_encoded_len++] = len_byte_ns;
    strcpy((char*)ns_dname_dns_format + ns_dname_encoded_len, ns_name_part);
    ns_dname_encoded_len += strlen(ns_name_part);
    ns_dname_dns_format[ns_dname_encoded_len++] = 0;

    // 设置NS记录RDATA长度并复制数据
    uint16_t* ns_rdlen_ptr = (uint16_t*)(response_buffer + current_pos);
    *ns_rdlen_ptr = htons(ns_dname_encoded_len); current_pos += 2;
    memcpy(response_buffer + current_pos, ns_dname_dns_format, ns_dname_encoded_len);
    current_pos += ns_dname_encoded_len;

    // 原始代码包含SOA记录，但NS记录对简单权威更常见
    // 如需SOA记录需要仔细构造
    // 当前版本仅包含权威部分的NS记录以保持简单

    // 发送构造好的PTR响应
    sendto(sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);
    printf("Sent PTR response for ID %u to %s:%d (Domain=%s)\n", ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), domain_to_send);
}

void send_nodata_response(SOCKET_TYPE sockfd, uint16_t original_id,
                          const unsigned char* original_qname_start_ptr, int original_qname_len,
                          uint16_t qtype, // The original qtype (e.g., AAAA)
                          const struct sockaddr_in* client_addr, socklen_t client_addr_len) {
    unsigned char response_buffer[DNS_BUFFER_SIZE];
    DNSHeader* res_hdr = (DNSHeader*)response_buffer;

    res_hdr->id = original_id;
    // Flags: Response, Authoritative (optional, but common for local "negative" answers), NoError
    // RA bit might not be strictly necessary for NODATA but doesn't hurt.
    // AA bit can be set if you consider your server authoritative for "no AAAA record here".
    res_hdr->flags = htons(0x8180); // 响应，RA=1，RCODE=0（无错误）
    // 替代选项：0x8580 如果你想要AA=1
    res_hdr->qdcount = htons(1);
    res_hdr->ancount = htons(0); // 关键：无答案
    res_hdr->nscount = htons(0); // 可选，如果你的区域有SOA记录，可以在这里添加
    res_hdr->arcount = htons(0);

    int current_pos = sizeof(DNSHeader);
    // 复制QNAME
    memcpy(response_buffer + current_pos, original_qname_start_ptr, original_qname_len);
    current_pos += original_qname_len;

    // 复制QTYPE, QCLASS来自原始查询
    DNSQuestionTail* q_tail_resp = (DNSQuestionTail*)(response_buffer + current_pos);
    q_tail_resp->qtype = htons(qtype);  // 使用原始qtype
    q_tail_resp->qclass = htons(1);     // IN
    current_pos += sizeof(DNSQuestionTail);

    // 无Answer记录。
    // 可选，如果你想更符合RFC规范进行负面缓存，可以在Authority部分添加SOA记录。
    // 为简单起见，我们在这里省略它。大多数客户端会很好地处理NoError/ANCOUNT=0。

    sendto(sockfd, (char*)response_buffer, current_pos, 0,
           (struct sockaddr*)client_addr, client_addr_len);

    char qtype_str[10];
    sprintf(qtype_str, "%hu", qtype);
    if (qtype == 28) strcpy(qtype_str, "AAAA");
    else if (qtype == 1) strcpy(qtype_str, "A");

    printf("Sent NODATA response for QTYPE %s, ID %u to %s:%d\n",
           qtype_str, ntohs(original_id),
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
}