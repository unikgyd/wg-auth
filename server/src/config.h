#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define MAX_PATH_LEN 256
#define MAX_IP_LEN   64
#define MAX_HOST_LEN 128

typedef struct {
    char wg_interface[MAX_PATH_LEN];
    char wg_conf_path[MAX_PATH_LEN];
    char endpoint_public_addr[MAX_HOST_LEN];
    char dns[MAX_IP_LEN];
    
    char api_listen_addr[MAX_IP_LEN];
    int api_listen_port;
    char tls_cert[MAX_PATH_LEN];
    char tls_key[MAX_PATH_LEN];
    
    char db_path[MAX_PATH_LEN];
    
    char ip_pool_cidr[MAX_IP_LEN];
    char ip_pool_exclude[MAX_IP_LEN];
    
    int session_default_ttl_seconds;
    int session_renew_grace_seconds;
    int session_reap_interval_seconds;
    
    int argon2_time_cost;
    int argon2_mem_cost_kb;
} server_config_t;

extern server_config_t g_config;

int load_config(const char *path);

#endif // CONFIG_H
