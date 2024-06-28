#include "logger.h"

void init_logger(struct Config *config) {

    // 设置日志处理器为标准输出
    hlog_set_handler(stdout_logger);
    // 设置日志等级 0: ERROR, 1: INFO, 2: DEBUG
    switch (config->debug_level) {
        case 0:
            hlog_set_level(LOG_LEVEL_ERROR);
            break;
        case 1:
            hlog_set_level(LOG_LEVEL_INFO);
            break;
        case 2:
            hlog_set_level(LOG_LEVEL_DEBUG);
            break;
        default:
            hlog_set_level(LOG_LEVEL_INFO);
            break;
    }

    // 启用日志颜色
    logger_enable_color(hlog, 0);
    // 设置日志格式
    hlog_set_format("%y-%m-%d %H:%M:%S.%z %L %s");
}