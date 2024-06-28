#pragma once

#include <stdint.h>

// 定义缓存结构
typedef struct cache_t cache_t;

// 创建缓存
cache_t* cache_create(int capacity);

// 销毁缓存
void cache_destroy(cache_t* cache);

// 插入缓存
void cache_insert(cache_t* cache, const char* key, const char* value);

// 从缓存获取
const char* cache_get(cache_t* cache, const char* key);
