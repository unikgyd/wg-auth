#include "config.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

server_config_t g_config;

static void set_default_config() {
    memset(&g_config, 0, sizeof(g_config));
    strcpy(g_config.wg_interface, "wg0");
    strcpy(g_config.wg_conf_path, "/etc/wireguard/wg0.conf");
    strcpy(g_config.api_listen_addr, "0.0.0.0");
    g_config.api_listen_port = 8443;
    g_config.session_default_ttl_seconds = 43200;
    g_config.session_reap_interval_seconds = 60;
    g_config.argon2_time_cost = 3;
    g_config.argon2_mem_cost_kb = 65536;
}

static char* trim(char *s) {
    while(isspace((unsigned char)*s)) s++;
    if(*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while(end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

int load_config(const char *path) {
    set_default_config();
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_WARN("Could not open config file %s, using defaults", path);
        return -1;
    }

    char line[512];
    char section[64] = {0};

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (p[0] == '#' || p[0] == ';' || p[0] == '\0') continue;

        if (p[0] == '[' && strchr(p, ']')) {
            char *end = strchr(p, ']');
            *end = '\0';
            strncpy(section, p + 1, sizeof(section)-1);
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        char *comment = strchr(val, ';');
        if (comment) {
            *comment = '\0';
            val = trim(val);
        }

        if (strcmp(section, "server") == 0) {
            if (strcmp(key, "wg_interface") == 0) strncpy(g_config.wg_interface, val, MAX_PATH_LEN-1);
            else if (strcmp(key, "wg_conf_path") == 0) strncpy(g_config.wg_conf_path, val, MAX_PATH_LEN-1);
            else if (strcmp(key, "endpoint_public_addr") == 0) strncpy(g_config.endpoint_public_addr, val, MAX_HOST_LEN-1);
            else if (strcmp(key, "dns") == 0) strncpy(g_config.dns, val, MAX_IP_LEN-1);
        } else if (strcmp(section, "api") == 0) {
            if (strcmp(key, "listen_addr") == 0) strncpy(g_config.api_listen_addr, val, MAX_IP_LEN-1);
            else if (strcmp(key, "listen_port") == 0) g_config.api_listen_port = atoi(val);
            else if (strcmp(key, "tls_cert") == 0) strncpy(g_config.tls_cert, val, MAX_PATH_LEN-1);
            else if (strcmp(key, "tls_key") == 0) strncpy(g_config.tls_key, val, MAX_PATH_LEN-1);
        } else if (strcmp(section, "db") == 0) {
            if (strcmp(key, "path") == 0) strncpy(g_config.db_path, val, MAX_PATH_LEN-1);
        } else if (strcmp(section, "ip_pool") == 0) {
            if (strcmp(key, "cidr") == 0) strncpy(g_config.ip_pool_cidr, val, MAX_IP_LEN-1);
            else if (strcmp(key, "exclude") == 0) strncpy(g_config.ip_pool_exclude, val, MAX_IP_LEN-1);
        } else if (strcmp(section, "session") == 0) {
            if (strcmp(key, "default_ttl_seconds") == 0) g_config.session_default_ttl_seconds = atoi(val);
            else if (strcmp(key, "renew_grace_seconds") == 0) g_config.session_renew_grace_seconds = atoi(val);
            else if (strcmp(key, "reap_interval_seconds") == 0) g_config.session_reap_interval_seconds = atoi(val);
        } else if (strcmp(section, "security") == 0) {
            if (strcmp(key, "argon2_time_cost") == 0) g_config.argon2_time_cost = atoi(val);
            else if (strcmp(key, "argon2_mem_cost_kb") == 0) g_config.argon2_mem_cost_kb = atoi(val);
        }
    }

    fclose(f);
    return 0;
}
