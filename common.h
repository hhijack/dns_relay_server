#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h> // 用于InetPton, inet_ntoa函数
#include <windows.h>  // 用于Sleep函数
#pragma comment(lib, "ws2_32.lib") // 链接ws2_32.lib库
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET closesocket
#define GET_LAST_ERROR WSAGetLastError()
#include <pthread.h> // 假设使用pthreads-win32或MinGW的winpthreads

#define MAX_DNS_ENTRIES 1000       // DNS表最大条目数
#define DNS_BUFFER_SIZE 512        // DNS缓冲区大小
#define EXTERNAL_DNS_SERVER "223.5.5.5" // 外部DNS服务器地址（阿里DNS）
#define FORWARD_TIMEOUT_SEC 2      // 转发查询超时时间（秒）
#define MAX_RETRIES 2              // 最大重试次数
#define MAX_UPSTREAM_INFO_LEN 64   // 上游服务器信息最大长度

// 在DNS响应中设置上游服务器信息
void set_upstream_server_info(unsigned char* response, int response_len, const char* upstream_server);

#endif // COMMON_H