#include "dns_server.h"

// 函数声明
static int check_cache(dns_server_t* server, dns_t* query, dns_t* response);
static void build_dns_response(dns_t* response, dns_t* query, int addr_cnt, const char* cached_value, int type);
static int perform_dns_lookup(dns_server_t* server, dns_t* query, dns_t* response);
static int load_blacklist(cache_t* blacklist, cache_t* cache, const char* filename);
static bool is_blacklisted(cache_t* blacklist, const char* domain);
/**
 * @brief 初始化DNS服务器
 *
 * @param server DNS服务器实例
 * @param config 服务器配置
 * @return 成功时返回0
 */
int dns_server_init(dns_server_t* server, struct Config* config) {
    server->loop = hloop_new(HLOOP_FLAG_AUTO_FREE);
    if (server->loop == NULL) {
        hloge("Failed to create event loop");
        return -1;
    }
    hio_t* io = hloop_create_udp_server(server->loop, "0.0.0.0", config->port);
    if (io == NULL) {
        hloge("Failed to create UDP server");
        return -1;
    }
    hio_set_context(io, server);
    // 设置read回调
    hio_setcb_read(io, on_recv);
    // 开始读取数据
    hio_read(io);

    server->config = config;
    server->cache = cache_create(config->cache_size);
    server->blacklist = cache_create(config->cache_size);
    if(load_blacklist(server->blacklist, server->cache, config->filename) != 0) {
        hloge("Failed to load blacklist");
        return -1;
    }

    hlogi("DNS Server initialized on port %d", config->port);
    return 0;
}

/**
 * @brief 启动DNS服务器
 *
 * @param server DNS服务器实例
 * @return 成功时返回0
 */
int dns_server_start(dns_server_t* server) {
    hlogi("DNS Server starting...");
    return hloop_run(server->loop);
}

/**
 * @brief 停止DNS服务器
 *
 * @param server DNS服务器实例
 * @return 成功时返回0
 */
int dns_server_stop(dns_server_t* server) {
    hlogi("DNS Server stopping...");
    hloop_stop(server->loop);
    cache_destroy(server->cache);
    cache_destroy(server->blacklist);
    return 0;
}

/**
 * @brief 接收数据回调函数
 *
 * @param io I/O对象
 * @param buf 缓冲区
 * @param readbytes 读取字节数
 */
static void on_recv(hio_t* io, void* buf, int readbytes) {
    sockaddr_u client_addr;
    socklen_t addrlen = sizeof(client_addr);
    getpeername(hio_fd(io), (struct sockaddr*)&client_addr, &addrlen);

    dns_t query;
    if (dns_unpack((char*)buf, readbytes, &query) < 0) {
        hloge("Failed to unpack DNS query");
        return;
    }

    on_dns_query(io, &query, &client_addr, addrlen);
}

/**
 * @brief 处理DNS查询
 *
 * @param io I/O对象
 * @param query DNS查询消息
 * @param client_addr 客户端地址
 * @param addrlen 地址长度
 */
static void on_dns_query(hio_t* io, dns_t* query, sockaddr_u* client_addr, socklen_t addrlen) {
    dns_t response;
    memset(&response, 0, sizeof(response));
    response.hdr.transaction_id = query->hdr.transaction_id;
    response.hdr.qr = DNS_RESPONSE;
    response.hdr.rd = query->hdr.rd;
    response.hdr.ra = 1;
    response.hdr.nquestion = query->hdr.nquestion;

    response.questions = (dns_rr_t*)malloc(sizeof(dns_rr_t) * query->hdr.nquestion);
    memcpy(response.questions, query->questions, sizeof(dns_rr_t) * query->hdr.nquestion);

    dns_server_t* server = (dns_server_t*)hio_context(io);
    bool blacklisted = is_blacklisted(server->blacklist, query->questions->name);

    if (!blacklisted && check_cache(server, query, &response)) {
        char buf[512];
        int len = dns_pack(&response, buf, sizeof(buf));
        if (len < 0) {
            hloge("Failed to pack DNS response");
            dns_free(&response);
            return;
        }
        // 缓存命中
        hlogi("Cache hit: %s", query->questions->name);
        hio_write(io, buf, len);
        dns_free(&response);
        return;
    }

    if (!blacklisted && perform_dns_lookup(server, query, &response) == 0) {
        char buf[512];
        int len = dns_pack(&response, buf, sizeof(buf));
        if (len < 0) {
            hloge("Failed to pack DNS response");
            dns_free(&response);
            return;
        }
        hlogd("Cache miss: %s", query->questions->name);
        hio_write(io, buf, len);

    } else {
        if(blacklisted) hlogi("Blacklisted: %s", query->questions->name);
        else    hloge("Not found: %s", query->questions->name);
        response.hdr.rcode = 3;
        char buf[512];
        int len = dns_pack(&response, buf, sizeof(buf));
        if (len < 0) {
            hloge("Failed to pack DNS response");
            dns_free(&response);
            return;
        }
        hio_write(io, buf, len);
    }
    dns_free(&response);
}

static int check_cache(dns_server_t* server, dns_t* query, dns_t* response) {
    // 判断是否是 A 查询
    if (query->questions->rtype != DNS_TYPE_A) {
        return 0;
    }
    const char* cached_value = cache_get(server->cache, query->questions->name);
    if (cached_value != NULL) {
        build_dns_response(response, query, 1, cached_value, query->questions->rtype);
        return 1;
    }
    return 0;
}

static void build_dns_response(dns_t* response, dns_t* query, int addr_cnt, const char* cached_value, int type) {
    response->hdr.nanswer = addr_cnt;
    response->answers = (dns_rr_t*)malloc(sizeof(dns_rr_t) * addr_cnt);
    for (int i = 0; i < addr_cnt; ++i) {
        dns_rr_t* rr = &response->answers[i];
        memcpy(rr, query->questions, sizeof(dns_rr_t));
        rr->rclass = DNS_CLASS_IN;
        rr->ttl = 3600;
        if (type == DNS_TYPE_A) {
            rr->rtype = DNS_TYPE_A;
            rr->datalen = 4;
            rr->data = (char*)malloc(4);
            memcpy(rr->data, cached_value + i * 4, 4); // 处理多个IPv4地址
        } else if (type == DNS_TYPE_AAAA) {
            rr->rtype = DNS_TYPE_AAAA;
            rr->datalen = 16;
            rr->data = (char*)malloc(16);
            memcpy(rr->data, cached_value + i * 16, 16); // 处理多个IPv6地址
        }
    }
}

static int perform_dns_lookup(dns_server_t* server, dns_t* query, dns_t* response) {
    int addr_cnt = 0;
    uint32_t addrs[10];
    uint8_t addrs6[10][16];
    int naddr = sizeof(addrs) / sizeof(addrs[0]);
    int naddr6 = sizeof(addrs6) / sizeof(addrs6[0]);

    if (query->questions->rtype == DNS_TYPE_A) {
        addr_cnt = nslookup(query->questions->name, addrs, naddr, server->config->dns_server_ipaddr);
        if (addr_cnt > 0) {
            build_dns_response(response, query, addr_cnt, (const char*)addrs, DNS_TYPE_A);
            // 如果有多个，只缓存第一个IPv4地址
            cache_insert(server->cache, query->questions->name, (const char*)&addrs[0]);
            hlogi("Cache insert: %s", query->questions->name);
        }
    } else if (query->questions->rtype == DNS_TYPE_AAAA) {
        addr_cnt = nslookup6(query->questions->name, addrs6, naddr6, server->config->dns_server_ipaddr);
        if (addr_cnt > 0) {
            build_dns_response(response, query, addr_cnt, (const char*)addrs6, DNS_TYPE_AAAA);
        }
    }

    return addr_cnt > 0 ? 0 : -1;
}

/**
 * @brief 加载黑名单
 *
 * @param blacklist 黑名单Trie树
 * @praam cache 缓存
 * @param filename 黑名单文件路径
 * @return 成功时返回0
 */
static int load_blacklist(cache_t* blacklist, cache_t* cache, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        // 去掉行末的换行符
        line[strcspn(line, "\n")] = '\0';

        // 用空格分割 IP 和域名
        char* ip = strtok(line, " ");
        char* domain = strtok(NULL, " ");

        if (ip != NULL && domain != NULL) {
            if (strcmp(ip, "0.0.0.0") == 0) {
                cache_insert(blacklist, domain, "");
            } else {
                uint32_t addr;
                inet_pton(AF_INET, ip, &addr); // 将IP地址转换成uint32_t
                cache_insert(cache, domain, (const char*)&addr);
            }
        }
    }

    fclose(file);
    return 0;
}

static bool is_blacklisted(cache_t* blacklist, const char* domain) {
    return cache_get(blacklist, domain) != NULL;
}