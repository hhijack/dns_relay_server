#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include "common.h"

typedef enum { A_RECORD, PTR_RECORD } RecordType; // 记录类型枚举

typedef struct {
    char ip[16];      // IP地址
    char domain[256]; // 域名
    RecordType record_type;  // 新增记录类型字段
} DNSEntry;

void load_dns_table(const char* filename); // 加载DNS表
DNSEntry* find_in_dns_table(const char* key, RecordType type); // 在DNS表中查找
int get_dns_table_size(); // 如果需要外部获取表大小

#endif // DNS_CACHE_H