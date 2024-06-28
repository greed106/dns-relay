#include "dns.h"
#include <hv/hdef.h>
#include <hv/hsocket.h>
#include <hv/herr.h>


/**
 * @brief 释放DNS消息中的资源记录
 *
 * @param dns 需要释放资源的DNS消息
 */
void dns_free(dns_t* dns) {
    SAFE_FREE(dns->questions);
    SAFE_FREE(dns->answers);
    SAFE_FREE(dns->authorities);
    SAFE_FREE(dns->addtionals);
}

/**
 * @brief 将域名编码为DNS格式
 *
 * @param domain 输入的域名，例如：www.example.com
 * @param buf 编码后的缓冲区
 * @return 成功时返回编码后的长度
 */
int dns_name_encode(const char* domain, char* buf) {
    const char* p = domain;
    char* plen = buf++;
    int buflen = 1;
    int len = 0;
    while (*p != '\0') {
        if (*p != '.') {
            ++len;
            *buf = *p;
        } else {
            *plen = len;
            plen = buf;
            len = 0;
        }
        ++p;
        ++buf;
        ++buflen;
    }
    *plen = len;
    *buf = '\0';
    if (len != 0) {
        ++buflen; // 包括最后的 '\0'
    }
    return buflen;
}

/**
 * @brief 将DNS格式的域名解码为普通格式
 *
 * @param buf 输入的编码后的缓冲区
 * @param domain 解码后的域名
 * @return 成功时返回解码后的长度
 */
int dns_name_decode(const char* buf, char* domain) {
    const char* p = buf;
    int len = *p++;
    int buflen = 1;
    while (*p != '\0') {
        if (len-- == 0) {
            len = *p;
            *domain = '.';
        } else {
            *domain = *p;
        }
        ++p;
        ++domain;
        ++buflen;
    }
    *domain = '\0';
    ++buflen; // 包括最后的 '\0'
    return buflen;
}

/**
 * @brief 打包DNS资源记录
 *
 * @param rr 输入的DNS资源记录
 * @param buf 输出的缓冲区
 * @param len 缓冲区长度
 * @return 成功时返回打包后的长度
 */
int dns_rr_pack(dns_rr_t* rr, char* buf, int len) {
    char* p = buf;
    char encoded_name[256];
    int encoded_namelen = dns_name_encode(rr->name, encoded_name);
    int packetlen = encoded_namelen + 2 + 2 + (rr->data ? (4+2+rr->datalen) : 0);
    if (len < packetlen) {
        return -1;
    }

    memcpy(p, encoded_name, encoded_namelen);
    p += encoded_namelen;
    uint16_t* pushort = (uint16_t*)p;
    *pushort = htons(rr->rtype);
    p += 2;
    pushort = (uint16_t*)p;
    *pushort = htons(rr->rclass);
    p += 2;

    if (rr->datalen && rr->data) {
        uint32_t* puint = (uint32_t*)p;
        *puint = htonl(rr->ttl);
        p += 4;
        pushort = (uint16_t*)p;
        *pushort = htons(rr->datalen);
        p += 2;
        memcpy(p, rr->data, rr->datalen);
        p += rr->datalen;
    }
    return packetlen;
}

/**
 * @brief 解包DNS资源记录
 *
 * @param buf 输入的缓冲区
 * @param len 缓冲区长度
 * @param rr 输出的DNS资源记录
 * @param is_question 是否是查询
 * @return 成功时返回解包后的长度
 */
int dns_rr_unpack(char* buf, int len, dns_rr_t* rr, int is_question) {
    char* p = buf;
    int off = 0;
    int namelen = 0;
    if (*(uint8_t*)p >= 192) {
        namelen = 2; // 名称偏移，忽略
    } else {
        namelen = dns_name_decode(buf, rr->name);
    }
    if (namelen < 0) return -1;
    p += namelen;
    off += namelen;

    if (len < off + 4) return -1;
    uint16_t* pushort = (uint16_t*)p;
    rr->rtype = ntohs(*pushort);
    p += 2;
    pushort = (uint16_t*)p;
    rr->rclass = ntohs(*pushort);
    p += 2;
    off += 4;

    if (!is_question) {
        if (len < off + 6) return -1;
        uint32_t* puint = (uint32_t*)p;
        rr->ttl = ntohl(*puint);
        p += 4;
        pushort = (uint16_t*)p;
        rr->datalen = ntohs(*pushort);
        p += 2;
        off += 6;
        if (len < off + rr->datalen) return -1;
        rr->data = p;
        p += rr->datalen;
        off += rr->datalen;
    }
    return off;
}

/**
 * @brief 打包DNS消息
 *
 * @param dns 输入的DNS消息
 * @param buf 输出的缓冲区
 * @param len 缓冲区长度
 * @return 成功时返回打包后的长度
 */
int dns_pack(dns_t* dns, char* buf, int len) {
    if (len < sizeof(dnshdr_t)) return -1;
    int off = 0;
    dnshdr_t* hdr = &dns->hdr;
    dnshdr_t htonhdr = dns->hdr;
    htonhdr.transaction_id = htons(hdr->transaction_id);
    htonhdr.nquestion = htons(hdr->nquestion);
    htonhdr.nanswer = htons(hdr->nanswer);
    htonhdr.nauthority = htons(hdr->nauthority);
    htonhdr.naddtional = htons(hdr->naddtional);
    memcpy(buf, &htonhdr, sizeof(dnshdr_t));
    off += sizeof(dnshdr_t);
    int i;
    for (i = 0; i < hdr->nquestion; ++i) {
        int packetlen = dns_rr_pack(dns->questions+i, buf+off, len-off);
        if (packetlen < 0) return -1;
        off += packetlen;
    }
    for (i = 0; i < hdr->nanswer; ++i) {
        int packetlen = dns_rr_pack(dns->answers+i, buf+off, len-off);
        if (packetlen < 0) return -1;
        off += packetlen;
    }
    for (i = 0; i < hdr->nauthority; ++i) {
        int packetlen = dns_rr_pack(dns->authorities+i, buf+off, len-off);
        if (packetlen < 0) return -1;
        off += packetlen;
    }
    for (i = 0; i < hdr->naddtional; ++i) {
        int packetlen = dns_rr_pack(dns->addtionals+i, buf+off, len-off);
        if (packetlen < 0) return -1;
        off += packetlen;
    }
    return off;
}

/**
 * @brief 解包DNS消息
 *
 * @param buf 输入的缓冲区
 * @param len 缓冲区长度
 * @param dns 输出的DNS消息
 * @return 成功时返回解包后的长度
 */
int dns_unpack(char* buf, int len, dns_t* dns) {
    memset(dns, 0, sizeof(dns_t));
    if (len < sizeof(dnshdr_t)) return -1;
    int off = 0;
    dnshdr_t* hdr = &dns->hdr;
    memcpy(hdr, buf, sizeof(dnshdr_t));
    off += sizeof(dnshdr_t);
    hdr->transaction_id = ntohs(hdr->transaction_id);
    hdr->nquestion = ntohs(hdr->nquestion);
    hdr->nanswer = ntohs(hdr->nanswer);
    hdr->nauthority = ntohs(hdr->nauthority);
    hdr->naddtional = ntohs(hdr->naddtional);
    int i;
    if (hdr->nquestion) {
        int bytes = hdr->nquestion * sizeof(dns_rr_t);
        SAFE_ALLOC(dns->questions, bytes);
        for (i = 0; i < hdr->nquestion; ++i) {
            int packetlen = dns_rr_unpack(buf+off, len-off, dns->questions+i, 1);
            if (packetlen < 0) return -1;
            off += packetlen;
        }
    }
    if (hdr->nanswer) {
        int bytes = hdr->nanswer * sizeof(dns_rr_t);
        SAFE_ALLOC(dns->answers, bytes);
        for (i = 0; i < hdr->nanswer; ++i) {
            int packetlen = dns_rr_unpack(buf+off, len-off, dns->answers+i, 0);
            if (packetlen < 0) return -1;
            off += packetlen;
        }
    }
    if (hdr->nauthority) {
        int bytes = hdr->nauthority * sizeof(dns_rr_t);
        SAFE_ALLOC(dns->authorities, bytes);
        for (i = 0; i < hdr->nauthority; ++i) {
            int packetlen = dns_rr_unpack(buf+off, len-off, dns->authorities+i, 0);
            if (packetlen < 0) return -1;
            off += packetlen;
        }
    }
    if (hdr->naddtional) {
        int bytes = hdr->naddtional * sizeof(dns_rr_t);
        SAFE_ALLOC(dns->addtionals, bytes);
        for (i = 0; i < hdr->naddtional; ++i) {
            int packetlen = dns_rr_unpack(buf+off, len-off, dns->addtionals+i, 0);
            if (packetlen < 0) return -1;
            off += packetlen;
        }
    }
    return off;
}

/**
 * @brief 发送DNS查询并接收响应
 *
 * @param query 输入的DNS查询消息
 * @param response 输出的DNS响应消息
 * @param nameserver DNS服务器地址
 * @return 成功时返回0
 */
int dns_query(dns_t* query, dns_t* response, const char* nameserver) {
    char buf[1024];
    int buflen = sizeof(buf);
    buflen = dns_pack(query, buf, buflen);
    if (buflen < 0) {
        return buflen;
    }
#ifdef OS_WIN
//    WSAInit();
#endif
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return ERR_SOCKET;
    }
    so_sndtimeo(sockfd, 5000);
    so_rcvtimeo(sockfd, 5000);
    int ret = 0;
    int nsend, nrecv;
    int nparse;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(nameserver);
    addr.sin_port = htons(DNS_PORT);
    nsend = sendto(sockfd, buf, buflen, 0, (struct sockaddr*)&addr, addrlen);
    if (nsend != buflen) {
        ret = ERR_SENDTO;
        goto error;
    }
    nrecv = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addrlen);
    if (nrecv <= 0) {
        ret = ERR_RECVFROM;
        goto error;
    }

    nparse = dns_unpack(buf, nrecv, response);
    if (nparse != nrecv) {
        ret = -ERR_INVALID_PACKAGE;
        goto error;
    }

    error:
    if (sockfd != INVALID_SOCKET) {
        closesocket(sockfd);
    }
    return ret;
}

/**
 * @brief 进行域名解析
 *
 * @param domain 输入的域名
 * @param addrs 输出的地址数组
 * @param naddr 地址数组的大小
 * @param nameserver DNS服务器地址
 * @return 成功时返回解析到的地址数量
 */
int nslookup(const char* domain, uint32_t* addrs, int naddr, const char* nameserver) {
    dns_t query;
    memset(&query, 0, sizeof(query));
    query.hdr.transaction_id = getpid();
    query.hdr.qr = DNS_QUERY;
    query.hdr.rd = 1;
    query.hdr.nquestion = 1;

    dns_rr_t question;
    memset(&question, 0, sizeof(question));
    strncpy(question.name, domain, sizeof(question.name));
    question.rtype = DNS_TYPE_A;
    question.rclass = DNS_CLASS_IN;

    query.questions = &question;

    dns_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = dns_query(&query, &resp, nameserver);
    if (ret != 0) {
        return ret;
    }

    dns_rr_t* rr = resp.answers;
    int addr_cnt = 0;
    if (resp.hdr.transaction_id != query.hdr.transaction_id ||
        resp.hdr.qr != DNS_RESPONSE ||
        resp.hdr.rcode != 0) {
        ret = -ERR_MISMATCH;
        goto end;
    }

    if (resp.hdr.nanswer == 0) {
        ret = 0;
        goto end;
    }

    for (int i = 0; i < resp.hdr.nanswer; ++i, ++rr) {
        if (rr->rtype == DNS_TYPE_A) {
            if (addr_cnt < naddr && rr->datalen == 4) {
                memcpy(addrs+addr_cnt, rr->data, 4);
            }
            ++addr_cnt;
        }
    }
    ret = addr_cnt;
    end:
    dns_free(&resp);
    return ret;
}

/**
 * @brief 进行IPv6域名解析
 *
 * @param domain 输入的域名
 * @param addrs 输出的IPv6地址数组
 * @param naddr 地址数组的大小
 * @param nameserver DNS服务器地址
 * @return 成功时返回解析到的地址数量
 */
int nslookup6(const char* domain, uint8_t addrs[][16], int naddr, const char* nameserver) {
    dns_t query;
    memset(&query, 0, sizeof(query));
    query.hdr.transaction_id = getpid();
    query.hdr.qr = DNS_QUERY;
    query.hdr.rd = 1;
    query.hdr.nquestion = 1;

    dns_rr_t question;
    memset(&question, 0, sizeof(question));
    strncpy(question.name, domain, sizeof(question.name));
    question.rtype = DNS_TYPE_AAAA;
    question.rclass = DNS_CLASS_IN;

    query.questions = &question;

    dns_t resp;
    memset(&resp, 0, sizeof(resp));
    int ret = dns_query(&query, &resp, nameserver);
    if (ret != 0) {
        return ret;
    }

    dns_rr_t* rr = resp.answers;
    int addr_cnt = 0;
    if (resp.hdr.transaction_id != query.hdr.transaction_id ||
        resp.hdr.qr != DNS_RESPONSE ||
        resp.hdr.rcode != 0) {
        ret = -ERR_MISMATCH;
        goto end;
    }

    if (resp.hdr.nanswer == 0) {
        ret = 0;
        goto end;
    }

    for (int i = 0; i < resp.hdr.nanswer; ++i, ++rr) {
        if (rr->rtype == DNS_TYPE_AAAA) {
            if (addr_cnt < naddr && rr->datalen == 16) {
                memcpy(addrs[addr_cnt], rr->data, 16);
                ++addr_cnt;
            }
        }
    }
    ret = addr_cnt;
    end:
    dns_free(&resp);
    return ret;
}

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

) {
    char buf[1024];
    int buflen = sizeof(buf);
    buflen = dns_pack(query, buf, buflen);
    if (buflen < 0) {
        return buflen;
    }

    // 设置上下文为response结构体，用于回调时使用
    hio_set_context(io, response);

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(nameserver);
    addr.sin_port = htons(DNS_PORT);

    // 设置远端地址
    hio_set_peeraddr(io, (struct sockaddr *) &addr, addrlen);

    // 发送数据
    hio_write(io, buf, buflen);

    // 设置读取回调
    hio_setcb_read(io, cb);

    // 开始读取响应数据
    hio_read(io);

    return 0;
}

/**
 * @brief DNS响应处理回调
 *
 * @param io I/O对象
 * @param buf 缓冲区
 * @param readbytes 读取字节数
 */
static void on_dns_response(hio_t* io, void* buf, int readbytes) {
    dns_t* response = (dns_t*)hio_context(io);

    int nparse = dns_unpack((char*)buf, readbytes, response);
    if (nparse < 0) {
        hloge("Failed to unpack DNS response");
        return;
    }

    // 处理DNS响应...
    hlogi("DNS response received");

    // 停止读取
    hio_close(io);
}