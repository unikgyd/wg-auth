#include "ip_pool.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

static uint32_t pool_start;
static uint32_t pool_end;
static uint32_t exclude_start;
static uint32_t exclude_end;

static uint8_t *bitmap = NULL;
static uint32_t num_ips = 0;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

static int parse_cidr(const char *cidr, uint32_t *start, uint32_t *end) {
    char ip_str[64];
    strncpy(ip_str, cidr, sizeof(ip_str)-1);
    ip_str[sizeof(ip_str)-1] = '\0';
    char *slash = strchr(ip_str, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return -1;
    
    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    *start = ip & mask;
    *end = *start | ~mask;
    return 0;
}

int ip_pool_init(const char *cidr, const char *exclude) {
    if (parse_cidr(cidr, &pool_start, &pool_end) != 0) {
        LOG_ERROR("Invalid IP pool CIDR: %s", cidr);
        return -1;
    }
    
    if (exclude && strlen(exclude) > 0) {
        if (parse_cidr(exclude, &exclude_start, &exclude_end) != 0) {
            LOG_ERROR("Invalid exclude CIDR: %s", exclude);
            exclude_start = 0;
            exclude_end = 0;
        }
    } else {
        exclude_start = 0;
        exclude_end = 0;
    }
    
    num_ips = pool_end - pool_start + 1;
    if (num_ips <= 2) {
        LOG_ERROR("IP pool too small");
        return -1;
    }
    
    bitmap = calloc(1, (num_ips + 7) / 8);
    if (!bitmap) return -1;
    
    // Mark network and broadcast address as used
    bitmap[0] |= 1;
    bitmap[(num_ips - 1) / 8] |= (1 << ((num_ips - 1) % 8));
    
    return 0;
}

int ip_pool_allocate(char *out_ip, int max_len) {
    pthread_mutex_lock(&pool_mutex);
    for (uint32_t i = 1; i < num_ips - 1; i++) {
        if (!(bitmap[i / 8] & (1 << (i % 8)))) {
            uint32_t ip = pool_start + i;
            if (ip >= exclude_start && ip <= exclude_end) {
                bitmap[i / 8] |= (1 << (i % 8));
                continue;
            }
            bitmap[i / 8] |= (1 << (i % 8));
            pthread_mutex_unlock(&pool_mutex);
            
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            char ip_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf));
            snprintf(out_ip, max_len, "%s/32", ip_buf);
            return 0;
        }
    }
    pthread_mutex_unlock(&pool_mutex);
    return -1;
}

int ip_pool_release(const char *ip_cidr) {
    char ip_str[64];
    strncpy(ip_str, ip_cidr, sizeof(ip_str)-1);
    ip_str[sizeof(ip_str)-1] = '\0';
    char *slash = strchr(ip_str, '/');
    if (slash) *slash = '\0';
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return -1;
    uint32_t ip = ntohl(addr.s_addr);
    
    if (ip < pool_start || ip > pool_end) return -1;
    
    uint32_t i = ip - pool_start;
    pthread_mutex_lock(&pool_mutex);
    bitmap[i / 8] &= ~(1 << (i % 8));
    pthread_mutex_unlock(&pool_mutex);
    return 0;
}

int ip_pool_mark_used(const char *ip_cidr) {
    char ip_str[64];
    strncpy(ip_str, ip_cidr, sizeof(ip_str)-1);
    ip_str[sizeof(ip_str)-1] = '\0';
    char *slash = strchr(ip_str, '/');
    if (slash) *slash = '\0';
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return -1;
    uint32_t ip = ntohl(addr.s_addr);
    
    if (ip < pool_start || ip > pool_end) return -1;
    
    uint32_t i = ip - pool_start;
    pthread_mutex_lock(&pool_mutex);
    bitmap[i / 8] |= (1 << (i % 8));
    pthread_mutex_unlock(&pool_mutex);
    return 0;
}
