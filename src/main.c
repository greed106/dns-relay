#include "args.h"
#include "logger.h"
#include "dns_server.h"

int main(int argc, char **argv) {
    // 服务器的配置信息
    struct Config server_config = {0};
    // 从命令行参数中解析出配置信息
    parse_args(argc, argv, &server_config);
    init_logger(&server_config);

    dns_server_t server;
    if(dns_server_init(&server, &server_config) != 0) {
        hloge("Failed to initialize DNS Server");
        return -1;
    }

    dns_server_start(&server);

    return 0;
}
