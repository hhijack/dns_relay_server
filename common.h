#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> // For InetPton, inet_ntoa
#include <windows.h>  // For Sleep
#pragma comment(lib, "ws2_32.lib") // Link with ws2_32.lib
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET closesocket
#define GET_LAST_ERROR WSAGetLastError()
#include <pthread.h> // Assuming pthreads-win32 or MinGW's winpthreads
#else // Linux / macOS
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#define SOCKET_TYPE int
#define INVALID_SOCKET -1
#define SOCKET_ERROR   -1
#define CLOSE_SOCKET close
#define GET_LAST_ERROR errno
#endif

#define MAX_DNS_ENTRIES 1000
#define DNS_BUFFER_SIZE 512
#define EXTERNAL_DNS_SERVER "223.5.5.5" // 阿里DNS
#define FORWARD_TIMEOUT_SEC 2           // 转发查询超时时间(秒)
#define MAX_RETRIES 2                   // 最大重试次数
#define MAX_UPSTREAM_INFO_LEN 64        // 上游服务器信息最大长度

// 在DNS响应中设置上游服务器信息
void set_upstream_server_info(unsigned char* response, int response_len, const char* upstream_server);

#endif // COMMON_H