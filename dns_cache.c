#include "dns_cache.h"

// ???????????????????????
static DNSEntry dns_table[MAX_DNS_ENTRIES]; // DNS??
static int dns_table_size = 0;              // DNS????С

void load_dns_table(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if(!fp) {
        printf("Warning: DNS table file '%s' not found or cannot be opened. Starting with an empty table.\n", filename);
        return;
    }

    char line[512];
    while(fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0; // Remove newline characters
        if(line[0] == '#' || line[0] == '\0' || isspace(line[0])) continue; // Skip comments and empty lines

        // 修改解析逻辑支持PTR记录
        char record_type_str[4], key_str[256], value_str[256];
        if(sscanf(line, "%3[^=]=%255[^,], Domain=%255s", record_type_str, key_str, value_str) == 3) {
            RecordType type = (strcmp(record_type_str, "PTR") == 0) ? PTR_RECORD : A_RECORD;
            
            strncpy(dns_table[dns_table_size].ip, (type == A_RECORD) ? key_str : value_str, 15);
            strncpy(dns_table[dns_table_size].domain, (type == A_RECORD) ? value_str : key_str, 255);
            dns_table[dns_table_size].record_type = type;
            printf("Loaded from file: IP=%s, Domain=%s\n", dns_table[dns_table_size].ip, dns_table[dns_table_size].domain);
            dns_table_size++;
        }
        char ip_str[16] = {0};
        char domain_str[256] = {0};
        if(sscanf(line, "%15s %255s", ip_str, domain_str) == 2) { // 兼容旧格式
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

DNSEntry* find_in_dns_table(const char* key, RecordType type) { // 修改函数签名
    for(int i = 0; i < dns_table_size; i++) {
        if(dns_table[i].record_type == type && 
          (type == A_RECORD ? strcmp(dns_table[i].domain, key) == 0 
                            : strcmp(dns_table[i].ip, key) == 0)) {
            return &dns_table[i];
        }
    }
    return NULL;
}

int get_dns_table_size() {
    return dns_table_size;
}