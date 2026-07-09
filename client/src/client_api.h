#ifndef CLIENT_API_H
#define CLIENT_API_H

#include <stdint.h>

typedef struct {
    char session_token[64];
    char client_private_key_b64[64];
    char client_address[64];
    char server_public_key_b64[64];
    char preshared_key_b64[64];
    char endpoint[128];
    char allowed_ips[256];
    char dns[64];
    int64_t expires_at;
} wg_client_config_t;

typedef struct {
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    int64_t last_handshake_time;
    int64_t expires_at;
} wg_client_status_t;

int client_api_init(const char *server_url, const char *ca_cert_path, int insecure);
void client_api_cleanup(void);

int client_api_login(const char *username, const char *password, wg_client_config_t *out_config);
int client_api_logout(const char *session_token);
int client_api_renew(const char *session_token, int64_t *out_new_expiry);
int client_api_status(const char *session_token, wg_client_status_t *out_stats);

#endif // CLIENT_API_H
