#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include "common.h"

typedef enum { A_RECORD, PTR_RECORD } RecordType;

typedef struct {
    char ip[16];      
    char domain[256]; 
    RecordType record_type;  // 新增记录类型字段
} DNSEntry;

void load_dns_table(const char* filename);
DNSEntry* find_in_dns_table(const char* key, RecordType type);
int get_dns_table_size(); // If needed externally

#endif // DNS_CACHE_H