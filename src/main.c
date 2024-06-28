#include "args.h"
#include "logger.h"
#include "dns_server.h"
#include <signal.h>

// 全局变量，用于在清理函数中访问DNS服务器实例
dns_server_t server;

// 清理函数，用于释放资源
static void cleanup(int status) {
    dns_server_stop(&server);
}

int main(int argc, char **argv) {
    // 服务器的配置信息
    struct Config server_config = {0};
    // 从命令行参数中解析出配置信息
    parse_args(argc, argv, &server_config);
    init_logger(&server_config);

    // 注册清理函数
    signal(SIGINT, cleanup);

    if(dns_server_init(&server, &server_config) != 0) {
        hloge("Failed to initialize DNS Server");
        return -1;
    }

    dns_server_start(&server);

    return 0;
}
