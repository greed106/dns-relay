#include "cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define N 38 // 0-9, -, ., A-Z, a-z 共 38 个字符

typedef struct lru_node_t {
    char* key;
    char* value;
    struct lru_node_t* prev;
    struct lru_node_t* next;
} lru_node_t;

typedef struct trie_node_t {
    struct trie_node_t* children[N];
    lru_node_t* lru_node;
    int is_end_of_word;
} trie_node_t;

struct cache_t {
    trie_node_t* root;
    lru_node_t* head;
    lru_node_t* tail;
    int capacity;
    int size;
};

// Helper functions for Trie and LRU
int char_to_index(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c == '-') return 10;
    if (c == '.') return 11;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 12;
    if (c >= 'a' && c <= 'z') return c - 'a' + 12;
    return -1;
}

trie_node_t* create_trie_node() {
    trie_node_t* node = (trie_node_t*)malloc(sizeof(trie_node_t));
    node->is_end_of_word = 0;
    node->lru_node = NULL;
    for (int i = 0; i < N; ++i) {
        node->children[i] = NULL;
    }
    return node;
}

lru_node_t* create_lru_node(const char* key, const char* value) {
    lru_node_t* node = (lru_node_t*)malloc(sizeof(lru_node_t));
    node->key = strdup(key);
    node->value = strdup(value);
    node->prev = NULL;
    node->next = NULL;
    return node;
}

// Cache functions
cache_t* cache_create(int capacity) {
    cache_t* cache = (cache_t*)malloc(sizeof(cache_t));
    cache->root = create_trie_node();
    cache->head = NULL;
    cache->tail = NULL;
    cache->capacity = capacity;
    cache->size = 0;
    return cache;
}

void free_trie_node(trie_node_t* node) {
    for (int i = 0; i < N; ++i) {
        if (node->children[i]) {
            free_trie_node(node->children[i]);
        }
    }
    free(node);
}

void cache_destroy(cache_t* cache) {
    // 释放LRU链表中的所有节点
    lru_node_t* current = cache->head;
    while (current) {
        lru_node_t* next = current->next;
        free(current->key);
        free(current->value);
        free(current);
        current = next;
    }

    // 释放Trie树中的所有节点
    free_trie_node(cache->root);

    // 释放cache结构体本身
    free(cache);
}

void cache_insert(cache_t* cache, const char* key, const char* value) {
    trie_node_t* node = cache->root;
    int length = strlen(key);
    for (int i = 0; i < length; ++i) {
        int index = char_to_index(key[i]);
        if (index == -1) continue;
        if (node->children[index] == NULL) {
            node->children[index] = create_trie_node();
        }
        node = node->children[index];
    }
    node->is_end_of_word = 1;

    if (node->lru_node) {
        lru_node_t* existing_node = node->lru_node;
        free(existing_node->value);
        existing_node->value = strdup(value);
        if (existing_node != cache->head) {
            if (existing_node->prev) existing_node->prev->next = existing_node->next;
            if (existing_node->next) existing_node->next->prev = existing_node->prev;
            if (existing_node == cache->tail) cache->tail = existing_node->prev;
            existing_node->next = cache->head;
            cache->head->prev = existing_node;
            existing_node->prev = NULL;
            cache->head = existing_node;
        }
        return;
    }

    lru_node_t* lru_node = create_lru_node(key, value);
    node->lru_node = lru_node;
    if (cache->size == cache->capacity) {
        lru_node_t* tail = cache->tail;
        cache->tail = tail->prev;
        if (cache->tail) cache->tail->next = NULL;
        trie_node_t* del_node = cache->root;
        int del_len = strlen(tail->key);
        for (int i = 0; i < del_len; ++i) {
            int index = char_to_index(tail->key[i]);
            if (index == -1) continue;
            del_node = del_node->children[index];
        }
        if (del_node) del_node->lru_node = NULL;
        free(tail->key);
        free(tail->value);
        free(tail);
        cache->size--;
    }
    lru_node->next = cache->head;
    if (cache->head) cache->head->prev = lru_node;
    cache->head = lru_node;
    if (cache->tail == NULL) cache->tail = lru_node;
    cache->size++;
}

const char* cache_get(cache_t* cache, const char* key) {
    trie_node_t* node = cache->root;
    int length = strlen(key);
    for (int i = 0; i < length; ++i) {
        int index = char_to_index(key[i]);
        if (index == -1) continue;
        if (node->children[index] == NULL) {
            return NULL;
        }
        node = node->children[index];
    }
    if (!node->is_end_of_word || !node->lru_node) {
        return NULL;
    }

    lru_node_t* lru_node = node->lru_node;
    if (lru_node == cache->head) {
        return lru_node->value;
    }

    if (lru_node->prev) lru_node->prev->next = lru_node->next;
    if (lru_node->next) lru_node->next->prev = lru_node->prev;
    if (lru_node == cache->tail) cache->tail = lru_node->prev;

    lru_node->next = cache->head;
    if (cache->head) cache->head->prev = lru_node;
    cache->head = lru_node;
    lru_node->prev = NULL;
    if (cache->tail == NULL) cache->tail = lru_node;

    return lru_node->value;
}
