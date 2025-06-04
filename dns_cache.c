//dns_cache.c
#include "dns_cache.h"
#include <stdio.h> // 确保包含stdio.h以使用printf/fprintf/FILE相关函数

// DNS缓存表实现
static DNSEntry dns_table[MAX_DNS_ENTRIES]; // DNS缓存表
static int dns_table_size = 0;              // DNS表当前大小

// 加载DNS表数据
void load_dns_table(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if(!fp) {
        printf("Warning: Unable to open DNS table file '%s'. Starting with empty table.\n", filename);
        return;
    }

    char line[512];
    while(fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0; // 移除换行符
        if(line[0] == '#' || line[0] == '\0' || isspace(line[0])) continue; // 跳过注释和空行

        char record_type_str[4], key_str[256], value_str[256];
        if(sscanf(line, "%3[^=]=%255[^,], Domain=%255s", record_type_str, key_str, value_str) == 3) {
            if (dns_table_size < MAX_DNS_ENTRIES) {
                RecordType type = (strcmp(record_type_str, "PTR") == 0) ? PTR_RECORD : A_RECORD;
                dns_table[dns_table_size].record_type = type;

                if (type == A_RECORD) {
                    // 对于A记录：key_str是IP地址，value_str是域名
                    // DNSEntry.ip存储IP地址，DNSEntry.domain存储域名
                    strncpy(dns_table[dns_table_size].ip, key_str, sizeof(dns_table[dns_table_size].ip) - 1);
                    dns_table[dns_table_size].ip[sizeof(dns_table[dns_table_size].ip) - 1] = '\0';
                    strncpy(dns_table[dns_table_size].domain, value_str, sizeof(dns_table[dns_table_size].domain) - 1);
                    dns_table[dns_table_size].domain[sizeof(dns_table[dns_table_size].domain) - 1] = '\0';
                } else { // PTR_RECORD
                    // 对于PTR记录：key_str是"x.x.x.x.in-addr.arpa"，value_str是"主机名"
                    // DNSEntry.domain存储"x.x.x.x.in-addr.arpa"（查找键）
                    // DNSEntry.ip存储"主机名"（结果，必须适合ip[16]）
                    strncpy(dns_table[dns_table_size].domain, key_str, sizeof(dns_table[dns_table_size].domain) - 1);
                    dns_table[dns_table_size].domain[sizeof(dns_table[dns_table_size].domain) - 1] = '\0';
                    strncpy(dns_table[dns_table_size].ip, value_str, sizeof(dns_table[dns_table_size].ip) - 1);
                    dns_table[dns_table_size].ip[sizeof(dns_table[dns_table_size].ip) - 1] = '\0';
                    if (strlen(value_str) >= sizeof(dns_table[dns_table_size].ip)) {
                        fprintf(stderr, "Warning: PTR record domain value '%s' might be truncated in ip field for key '%s'\n", value_str, key_str);
                    }
                }
                printf("Loaded from file: Type=%s, Key=%s, Value=%s\n", record_type_str, key_str, value_str);
                dns_table_size++;
            } else {
                fprintf(stderr, "Error: DNS table is full, cannot load more entries from new format.\n");
                break;
            }
        } else {
            char ip_str[16] = {0};
            char domain_str[256] = {0};
            if(sscanf(line, "%15s %255s", ip_str, domain_str) == 2) { // 兼容旧格式 (A记录)
                if(dns_table_size < MAX_DNS_ENTRIES) {
                    dns_table[dns_table_size].record_type = A_RECORD;
                    strncpy(dns_table[dns_table_size].ip, ip_str, sizeof(dns_table[dns_table_size].ip)-1);
                    dns_table[dns_table_size].ip[sizeof(dns_table[dns_table_size].ip)-1] = '\0';
                    strncpy(dns_table[dns_table_size].domain, domain_str, sizeof(dns_table[dns_table_size].domain)-1);
                    dns_table[dns_table_size].domain[sizeof(dns_table[dns_table_size].domain)-1] = '\0';
                    printf("Loaded from file (old format): IP=%s, Domain=%s\n", dns_table[dns_table_size].ip, dns_table[dns_table_size].domain);
                    dns_table_size++;
                } else {
                    fprintf(stderr, "Error: DNS table is full, cannot load more entries from old format.\n");
                    break;
                }
            } else {
                fprintf(stderr, "Warning: Malformed line in %s file: %s\n", filename, line);
            }
        }
    }
    fclose(fp);
}

// 在DNS表中查找条目
DNSEntry* find_in_dns_table(const char* key, RecordType type) {
    for(int i = 0; i < dns_table_size; i++) {
        if(dns_table[i].record_type == type) {
            if (type == A_RECORD) {
                // 对于A记录，key是域名，与entry.domain比较
                if (strcmp(dns_table[i].domain, key) == 0) {
                    return &dns_table[i];
                }
            } else { // PTR_RECORD
                // 对于PTR记录，key是"x.x.x.x.in-addr.arpa"，与entry.domain（存储位置）比较
                if (strcmp(dns_table[i].domain, key) == 0) {
                    return &dns_table[i];
                }
            }
        }
    }
    return NULL;
}

// 获取DNS表大小
int get_dns_table_size() {
    return dns_table_size;
}