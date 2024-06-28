#pragma once

#include <hv/hexport.h>
#include <hv/hplatform.h>
#include <hv/hsocket.h>
#include "logger.h"
#include <hv/hloop.h>

// 定义DNS服务器端口
#define DNS_PORT        53

// 定义DNS查询类型和响应类型
#define DNS_QUERY       0
#define DNS_RESPONSE    1

// 定义DNS记录类型
#define DNS_TYPE_A      1   // IPv4地址
#define DNS_TYPE_NS     2   // 名称服务器
#define DNS_TYPE_CNAME  5   // 规范名称
#define DNS_TYPE_SOA    6   // 起始授权机构
#define DNS_TYPE_WKS    11  // 熟知服务
#define DNS_TYPE_PTR    12  // 指针记录
#define DNS_TYPE_HINFO  13  // 主机信息
#define DNS_TYPE_MX     15  // 邮件交换记录
#define DNS_TYPE_AAAA   28  // IPv6地址
#define DNS_TYPE_AXFR   252 // 区域传送
#define DNS_TYPE_ANY    255 // 任意记录类型

// 定义DNS类
#define DNS_CLASS_IN    1   // 互联网

// 定义DNS名称的最大长度
#define DNS_NAME_MAXLEN 256

// DNS报头结构体，大小为12字节
typedef struct dnshdr_s {
    uint16_t    transaction_id;  // 事务ID，用于匹配请求和响应
    // 标志字段，根据字节序定义
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t     rd:1;            // 期望递归
    uint8_t     tc:1;            // 截断的消息
    uint8_t     aa:1;            // 授权回答
    uint8_t     opcode:4;        // 操作码
    uint8_t     qr:1;            // 查询/响应标志

    uint8_t     rcode:4;         // 响应码
    uint8_t     cd:1;            // 检查禁用
    uint8_t     ad:1;            // 已认证数据
    uint8_t     res:1;           // 保留
    uint8_t     ra:1;            // 递归可用
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t    qr:1;   // 查询/响应标志
    uint8_t    opcode:4; // 操作码
    uint8_t    aa:1;   // 授权回答
    uint8_t    tc:1;   // 截断的消息
    uint8_t    rd:1;   // 期望递归

    uint8_t    ra:1;   // 递归可用
    uint8_t    res:1;  // 保留
    uint8_t    ad:1;   // 已认证数据
    uint8_t    cd:1;   // 检查禁用
    uint8_t    rcode:4; // 响应码
#else
#error "BYTE_ORDER undefined!"
#endif
    uint16_t    nquestion;  // 问题数目
    uint16_t    nanswer;    // 回答数目
    uint16_t    nauthority; // 权威记录数目
    uint16_t    naddtional; // 附加记录数目
} dnshdr_t;

// DNS资源记录结构体
typedef struct dns_rr_s {
    char        name[DNS_NAME_MAXLEN]; // 原始域名，例如：www.example.com
    uint16_t    rtype;                 // 记录类型
    uint16_t    rclass;                // 记录类
    uint32_t    ttl;                   // 生存时间
    uint16_t    datalen;               // 数据长度
    char*       data;                  // 数据指针
} dns_rr_t;

// DNS消息结构体
typedef struct dns_s {
    dnshdr_t        hdr;          // DNS报头
    dns_rr_t*       questions;    // 查询问题
    dns_rr_t*       answers;      // 回答记录
    dns_rr_t*       authorities;  // 权威记录
    dns_rr_t*       addtionals;   // 附加记录
} dns_t;

BEGIN_EXTERN_C

/**
 * @brief 将域名编码为DNS格式
 *
 * 将域名从普通格式（如 www.example.com）转换为DNS格式（如 3www7example3com）。
 *
 * @param domain 输入的域名，例如：www.example.com
 * @param buf 编码后的缓冲区
 * @return 成功时返回编码后的长度
 */
int dns_name_encode(const char* domain, char* buf);

/**
 * @brief 将DNS格式的域名解码为普通格式
 *
 * 将DNS格式的域名（如 3www7example3com）转换回普通格式（如 www.example.com）。
 *
 * @param buf 输入的编码后的缓冲区
 * @param domain 解码后的域名
 * @return 成功时返回解码后的长度
 */
int dns_name_decode(const char* buf, char* domain);

/**
 * @brief 打包DNS资源记录
 *
 * 将DNS资源记录打包成二进制格式，以便发送。
 *
 * @param rr 输入的DNS资源记录
 * @param buf 输出的缓冲区
 * @param len 缓冲区长度
 * @return 成功时返回打包后的长度
 */
int dns_rr_pack(dns_rr_t* rr, char* buf, int len);

/**
 * @brief 解包DNS资源记录
 *
 * 将二进制格式的资源记录解包成结构化格式，以便处理。
 *
 * @param buf 输入的缓冲区
 * @param len 缓冲区长度
 * @param rr 输出的DNS资源记录
 * @param is_question 是否是查询
 * @return 成功时返回解包后的长度
 */
int dns_rr_unpack(char* buf, int len, dns_rr_t* rr, int is_question);

/**
 * @brief 打包DNS消息
 *
 * 将整个DNS消息打包，包括报头和所有资源记录。
 *
 * @param dns 输入的DNS消息
 * @param buf 输出的缓冲区
 * @param len 缓冲区长度
 * @return 成功时返回打包后的长度
 */
int dns_pack(dns_t* dns, char* buf, int len);

/**
 * @brief 解包DNS消息
 *
 * 将接收到的DNS消息解包成结构化格式，供进一步处理。
 *
 * @param buf 输入的缓冲区
 * @param len 缓冲区长度
 * @param dns 输出的DNS消息
 * @return 成功时返回解包后的长度
 */
int dns_unpack(char* buf, int len, dns_t* dns);

/**
 * @brief 释放DNS消息中分配的资源记录
 *
 * 释放DNS消息中动态分配的资源记录内存。
 *
 * @param dns 需要释放资源的DNS消息
 */
void dns_free(dns_t* dns);

/**
 * @brief 发送DNS查询并接收响应
 *
 * 发送DNS查询消息并接收响应消息，包括创建套接字、设置超时、发送和接收数据，以及解包响应消息。
 *
 * @param query 输入的DNS查询消息
 * @param response 输出的DNS响应消息
 * @param nameserver DNS服务器地址，默认值为"127.0.1.1"
 * @return 成功时返回0
 */
int dns_query(dns_t* query, dns_t* response, const char* nameserver DEFAULT("127.0.1.1"));

/**
 * @brief 进行域名解析
 *
 * 发送DNS查询以获取域名对应的IP地址。
 *
 * @param domain 输入的域名
 * @param addrs 输出的地址数组
 * @param naddr 地址数组的大小
 * @param nameserver DNS服务器地址，默认值为"127.0.1.1"
 * @return 成功时返回解析到的地址数量
 */
int nslookup(const char* domain, uint32_t* addrs, int naddr, const char* nameserver DEFAULT("127.0.1.1"));

/**
 * @brief 进行IPv6域名解析
 *
 * @param domain 输入的域名
 * @param addrs 输出的IPv6地址数组
 * @param naddr 地址数组的大小
 * @param nameserver DNS服务器地址
 * @return 成功时返回解析到的地址数量
 */
int nslookup6(const char* domain, uint8_t addrs[][16], int naddr, const char* nameserver);

/**
 * @brief 异步发送DNS查询并接收响应
 *
 * @param query 输入的DNS查询消息
 * @param response 输出的DNS响应消息
 * @param nameserver DNS服务器地址
 * @param io 传入的hio对象
 * @param cb 查询完成后的回调函数
 * @return 成功时返回0
 */
int dns_query_async(dns_t* query, dns_t* response, const char* nameserver, hio_t* io,

                    void (*cb)(hio_t *, void *, int)

);


END_EXTERN_C