#pragma once

#include <hv/hexport.h>
#include <hv/hloop.h>
#include <hv/hsocket.h>
#include <hv/hbuf.h>
#include "dns.h"
#include "args.h"
#include "logger.h"
#include "cache.h"

typedef struct {
    // 事件循环
    hloop_t* loop;
    // 服务器配置
    struct Config* config;
    // 缓存
    cache_t* cache;
    // 黑名单
    cache_t* blacklist;
} dns_server_t;

/**
 * @brief 初始化DNS服务器
 *
 * @param server DNS服务器实例
 * @param config 服务器配置
 * @return 成功时返回0
 */
int dns_server_init(dns_server_t* server, struct Config* config);

/**
 * @brief 启动DNS服务器
 *
 * @param server DNS服务器实例
 * @return 成功时返回0
 */
int dns_server_start(dns_server_t* server);

/**
 * @brief 停止DNS服务器
 *
 * @param server DNS服务器实例
 * @return 成功时返回0
 */
int dns_server_stop(dns_server_t* server);



// 内部函数
static void on_recv(hio_t* io, void* buf, int readbytes);
static void on_dns_query(hio_t* io, dns_t* query, sockaddr_u* client_addr, socklen_t addrlen);