#include "api_handlers.h"
#include "config.h"
#include "util.h"
#include "auth.h"
#include "db.h"
#include "ip_pool.h"
#include "wg_ctl.h"

#include <microhttpd.h>
#include <cJSON.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* --------------- constants --------------- */

#define MAX_BODY_SIZE       4096
#define MAX_FAIL_ENTRIES    256
#define MAX_FAILS_PER_IP    5
#define FAIL_WINDOW_SECONDS 600

/* --------------- static state ------------ */

static struct MHD_Daemon *api_daemon = NULL;

static uint8_t server_pubkey[WG_KEY_LEN];
static int     server_pubkey_loaded = 0;

/* --------------- rate limiter ------------ */

static struct {
    char   ip[64];
    time_t timestamp;
} fail_log[MAX_FAIL_ENTRIES];

static int             fail_log_idx = 0;
static pthread_mutex_t fail_mutex   = PTHREAD_MUTEX_INITIALIZER;

static void record_login_failure(const char *ip) {
    pthread_mutex_lock(&fail_mutex);
    strncpy(fail_log[fail_log_idx].ip, ip, sizeof(fail_log[fail_log_idx].ip) - 1);
    fail_log[fail_log_idx].ip[sizeof(fail_log[fail_log_idx].ip) - 1] = '\0';
    fail_log[fail_log_idx].timestamp = time(NULL);
    fail_log_idx = (fail_log_idx + 1) % MAX_FAIL_ENTRIES;
    pthread_mutex_unlock(&fail_mutex);
}

/* Returns 1 if the IP has exceeded the rate limit, 0 otherwise. */
static int check_rate_limit(const char *ip) {
    time_t now = time(NULL);
    int    count = 0;

    pthread_mutex_lock(&fail_mutex);
    for (int i = 0; i < MAX_FAIL_ENTRIES; i++) {
        if (fail_log[i].ip[0] &&
            strcmp(fail_log[i].ip, ip) == 0 &&
            now - fail_log[i].timestamp < FAIL_WINDOW_SECONDS) {
            count++;
        }
    }
    pthread_mutex_unlock(&fail_mutex);

    return count >= MAX_FAILS_PER_IP;
}

/* --------------- helpers ----------------- */

static char *read_file_to_string(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("read_file_to_string: cannot open %s", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t nread = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[nread] = '\0';
    return buf;
}

static const char *get_client_ip(struct MHD_Connection *connection) {
    const union MHD_ConnectionInfo *ci =
        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (!ci || !ci->client_addr)
        return "unknown";

    static __thread char addr_buf[64];
    struct sockaddr *sa = ci->client_addr;
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &sin->sin_addr, addr_buf, sizeof(addr_buf));
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, sizeof(addr_buf));
    } else {
        return "unknown";
    }
    return addr_buf;
}

static void api_cache_server_pubkey(void) {
    if (wgctl_get_server_pubkey(g_config.wg_interface, server_pubkey) == 0) {
        server_pubkey_loaded = 1;
        LOG_INFO("Cached WireGuard server public key");
    } else {
        LOG_ERROR("Failed to cache WireGuard server public key");
    }
}

/* --------------- JSON response ----------- */

static enum MHD_Result send_json_response(struct MHD_Connection *connection,
                                          cJSON *json, int status_code) {
    char *resp_str = cJSON_PrintUnformatted(json);
    if (!resp_str) {
        /* Fallback if cJSON_PrintUnformatted fails (OOM) */
        static const char oom_msg[] = "{\"error\":\"internal error\"}";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            sizeof(oom_msg) - 1, (void *)oom_msg, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(connection,
                                                 MHD_HTTP_INTERNAL_SERVER_ERROR,
                                                 response);
        MHD_destroy_response(response);
        return ret;
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(resp_str), (void *)resp_str, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

/* --------------- POST /login ------------- */

static enum MHD_Result handle_login(struct MHD_Connection *connection,
                                    const char *body) {
    /* --- rate limit check --- */
    const char *client_ip = get_client_ip(connection);
    if (check_rate_limit(client_ip)) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Too many failed attempts, try again later");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_TOO_MANY_REQUESTS);
        cJSON_Delete(err);
        return ret;
    }

    cJSON *json = cJSON_Parse(body);
    if (!json) return MHD_NO;

    cJSON *c_user = cJSON_GetObjectItem(json, "username");
    cJSON *c_pass = cJSON_GetObjectItem(json, "password");
    if (!c_user || !c_pass) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing username or password");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_BAD_REQUEST);
        cJSON_Delete(err);
        return ret;
    }

    account_t acc;
    if (db_get_account_by_username(c_user->valuestring, &acc) != 0) {
        cJSON_Delete(json);
        record_login_failure(client_ip);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid credentials");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_UNAUTHORIZED);
        cJSON_Delete(err);
        return ret;
    }

    if (acc.disabled) {
        cJSON_Delete(json);
        record_login_failure(client_ip);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Account disabled");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_FORBIDDEN);
        cJSON_Delete(err);
        return ret;
    }

    if (auth_verify_password(acc.password_hash, c_pass->valuestring) != 0) {
        cJSON_Delete(json);
        record_login_failure(client_ip);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid credentials");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_UNAUTHORIZED);
        cJSON_Delete(err);
        return ret;
    }

    uint8_t pubkey[WG_KEY_LEN], privkey[WG_KEY_LEN], psk[WG_KEY_LEN];
    auth_generate_keypair(pubkey, privkey);
    auth_generate_psk(psk);

    char ip[32];
    if (ip_pool_allocate(ip, sizeof(ip)) != 0) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "IP pool exhausted");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_SERVICE_UNAVAILABLE);
        cJSON_Delete(err);
        return ret;
    }

    if (wgctl_add_peer(g_config.wg_interface, pubkey, psk, ip) != 0) {
        ip_pool_release(ip);
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Failed to add peer to wg interface");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_INTERNAL_SERVER_ERROR);
        cJSON_Delete(err);
        return ret;
    }

    /* PSK no longer needed in raw form after adding peer */
    char psk_b64[64];
    base64_encode(psk, WG_KEY_LEN, psk_b64, sizeof(psk_b64));
    sodium_memzero(psk, sizeof(psk));

    char token[64];
    auth_generate_token(token, sizeof(token));
    int64_t expires_at = time(NULL) + g_config.session_default_ttl_seconds;

    char pub_b64[64];
    base64_encode(pubkey, WG_KEY_LEN, pub_b64, sizeof(pub_b64));

    if (db_create_session(acc.id, pub_b64, ip, token, expires_at) != 0) {
        wgctl_remove_peer(g_config.wg_interface, pubkey);
        ip_pool_release(ip);
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Failed to create session in DB");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_INTERNAL_SERVER_ERROR);
        cJSON_Delete(err);
        return ret;
    }

    db_log_audit(acc.id, "login", ip);

    char priv_b64[64];
    base64_encode(privkey, WG_KEY_LEN, priv_b64, sizeof(priv_b64));
    sodium_memzero(privkey, sizeof(privkey));

    /* Server public key */
    char srv_pub_b64[64];
    if (server_pubkey_loaded) {
        base64_encode(server_pubkey, WG_KEY_LEN, srv_pub_b64, sizeof(srv_pub_b64));
    } else {
        strncpy(srv_pub_b64, "<UNKNOWN>", sizeof(srv_pub_b64));
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "session_token", token);
    cJSON_AddStringToObject(resp, "client_private_key", priv_b64);
    cJSON_AddStringToObject(resp, "client_address", ip);
    cJSON_AddStringToObject(resp, "server_public_key", srv_pub_b64);
    cJSON_AddStringToObject(resp, "preshared_key", psk_b64);
    cJSON_AddStringToObject(resp, "endpoint", g_config.endpoint_public_addr);
    cJSON_AddStringToObject(resp, "allowed_ips", "10.8.0.0/16");
    cJSON_AddStringToObject(resp, "dns", g_config.dns);
    cJSON_AddNumberToObject(resp, "expires_at", expires_at);

    enum MHD_Result ret = send_json_response(connection, resp, MHD_HTTP_OK);

    /* Wipe sensitive key material from stack buffers */
    sodium_memzero(priv_b64, sizeof(priv_b64));
    sodium_memzero(psk_b64, sizeof(psk_b64));

    cJSON_Delete(json);
    cJSON_Delete(resp);

    return ret;
}

/* --------------- POST /logout ------------ */

static enum MHD_Result handle_logout(struct MHD_Connection *connection,
                                     const char *body) {
    cJSON *json = cJSON_Parse(body);
    if (!json) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid JSON");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_BAD_REQUEST);
        cJSON_Delete(err);
        return ret;
    }

    cJSON *c_token = cJSON_GetObjectItem(json, "session_token");
    if (!c_token || !cJSON_IsString(c_token)) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing session_token");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_BAD_REQUEST);
        cJSON_Delete(err);
        return ret;
    }

    session_t sess;
    if (db_get_session_by_token(c_token->valuestring, &sess) != 0) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session not found");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_NOT_FOUND);
        cJSON_Delete(err);
        return ret;
    }

    if (sess.revoked) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session already revoked");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_CONFLICT);
        cJSON_Delete(err);
        return ret;
    }

    /* Decode device pubkey so we can remove the WireGuard peer */
    uint8_t dev_pubkey[WG_KEY_LEN];
    size_t  dec_len = 0;
    if (base64_decode(sess.device_pubkey, dev_pubkey, sizeof(dev_pubkey), &dec_len) != 0 ||
        dec_len != WG_KEY_LEN) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid device pubkey in session");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_INTERNAL_SERVER_ERROR);
        cJSON_Delete(err);
        return ret;
    }

    wgctl_remove_peer(g_config.wg_interface, dev_pubkey);
    ip_pool_release(sess.allowed_ip);
    db_revoke_session(sess.id);
    db_log_audit(sess.account_id, "logout", sess.allowed_ip);

    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    enum MHD_Result ret = send_json_response(connection, resp, MHD_HTTP_OK);
    cJSON_Delete(resp);
    return ret;
}

/* --------------- POST /renew ------------- */

static enum MHD_Result handle_renew(struct MHD_Connection *connection,
                                    const char *body) {
    cJSON *json = cJSON_Parse(body);
    if (!json) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid JSON");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_BAD_REQUEST);
        cJSON_Delete(err);
        return ret;
    }

    cJSON *c_token = cJSON_GetObjectItem(json, "session_token");
    if (!c_token || !cJSON_IsString(c_token)) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing session_token");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_BAD_REQUEST);
        cJSON_Delete(err);
        return ret;
    }

    session_t sess;
    if (db_get_session_by_token(c_token->valuestring, &sess) != 0) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session not found");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_NOT_FOUND);
        cJSON_Delete(err);
        return ret;
    }

    if (sess.revoked) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session revoked");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_FORBIDDEN);
        cJSON_Delete(err);
        return ret;
    }

    time_t now = time(NULL);
    /* Allow renewal within the grace period after expiry */
    if (sess.expires_at + g_config.session_renew_grace_seconds < now) {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session expired beyond grace period");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_FORBIDDEN);
        cJSON_Delete(err);
        return ret;
    }

    int64_t new_expires = now + g_config.session_default_ttl_seconds;
    db_update_session_expiry(sess.id, new_expires);
    db_log_audit(sess.account_id, "renew", sess.allowed_ip);

    cJSON_Delete(json);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddNumberToObject(resp, "expires_at", new_expires);
    enum MHD_Result ret = send_json_response(connection, resp, MHD_HTTP_OK);
    cJSON_Delete(resp);
    return ret;
}

/* --------------- GET /status ------------- */

static enum MHD_Result handle_status(struct MHD_Connection *connection) {
    /* Try Authorization header first, then query parameter */
    const char *token = NULL;
    const char *auth = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                                   "Authorization");
    if (auth && strncmp(auth, "Bearer ", 7) == 0) {
        token = auth + 7;
    }
    if (!token) {
        token = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                            "token");
    }
    if (!token || token[0] == '\0') {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing token");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_UNAUTHORIZED);
        cJSON_Delete(err);
        return ret;
    }

    session_t sess;
    if (db_get_session_by_token(token, &sess) != 0) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session not found");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_NOT_FOUND);
        cJSON_Delete(err);
        return ret;
    }

    if (sess.revoked) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session revoked");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_FORBIDDEN);
        cJSON_Delete(err);
        return ret;
    }

    time_t now = time(NULL);
    if (sess.expires_at < now) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Session expired");
        enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_FORBIDDEN);
        cJSON_Delete(err);
        return ret;
    }

    /* Retrieve WireGuard peer traffic stats */
    uint8_t dev_pubkey[WG_KEY_LEN];
    size_t  dec_len = 0;
    uint64_t rx_bytes = 0, tx_bytes = 0;
    int64_t  last_handshake_time = 0;

    if (base64_decode(sess.device_pubkey, dev_pubkey, sizeof(dev_pubkey), &dec_len) == 0 &&
        dec_len == WG_KEY_LEN) {
        wgctl_get_peer_stats(g_config.wg_interface, dev_pubkey,
                             &rx_bytes, &tx_bytes, &last_handshake_time);
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "active");
    cJSON_AddStringToObject(resp, "allowed_ip", sess.allowed_ip);
    cJSON_AddNumberToObject(resp, "expires_at", sess.expires_at);
    cJSON_AddNumberToObject(resp, "rx_bytes", (double)rx_bytes);
    cJSON_AddNumberToObject(resp, "tx_bytes", (double)tx_bytes);
    cJSON_AddNumberToObject(resp, "last_handshake_time", (double)last_handshake_time);

    enum MHD_Result ret = send_json_response(connection, resp, MHD_HTTP_OK);
    cJSON_Delete(resp);
    return ret;
}

/* --------------- router / MHD glue ------- */

struct connection_info {
    char  *data;
    size_t size;
};

static void request_completed(void *cls, struct MHD_Connection *connection,
                              void **con_cls,
                              enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;
    struct connection_info *info = *con_cls;
    if (info) {
        if (info->data) free(info->data);
        free(info);
    }
}

static enum MHD_Result api_router(void *cls, struct MHD_Connection *connection,
                                  const char *url, const char *method,
                                  const char *version,
                                  const char *upload_data,
                                  size_t *upload_data_size,
                                  void **con_cls) {
    (void)cls;
    (void)version;

    if (*con_cls == NULL) {
        struct connection_info *info = calloc(1, sizeof(struct connection_info));
        *con_cls = info;
        return MHD_YES;
    }

    struct connection_info *info = *con_cls;

    if (*upload_data_size != 0) {
        /* Body size limit */
        if (info->size + *upload_data_size > MAX_BODY_SIZE) {
            *upload_data_size = 0;
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "error", "Request body too large");
            enum MHD_Result ret = send_json_response(connection, err,
                                                     MHD_HTTP_CONTENT_TOO_LARGE);
            cJSON_Delete(err);
            return ret;
        }
        info->data = realloc(info->data, info->size + *upload_data_size + 1);
        memcpy(info->data + info->size, upload_data, *upload_data_size);
        info->size += *upload_data_size;
        info->data[info->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* ---- route dispatch ---- */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/login") == 0) {
        return handle_login(connection, info->data ? info->data : "");
    }
    if (strcmp(method, "POST") == 0 && strcmp(url, "/logout") == 0) {
        return handle_logout(connection, info->data ? info->data : "");
    }
    if (strcmp(method, "POST") == 0 && strcmp(url, "/renew") == 0) {
        return handle_renew(connection, info->data ? info->data : "");
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/status") == 0) {
        return handle_status(connection);
    }

    cJSON *err = cJSON_CreateObject();
    cJSON_AddStringToObject(err, "error", "Not found");
    enum MHD_Result ret = send_json_response(connection, err, MHD_HTTP_NOT_FOUND);
    cJSON_Delete(err);
    return ret;
}

/* --------------- start / stop ------------ */

int api_start(void) {
    /* Cache the server WireGuard public key */
    api_cache_server_pubkey();

    /* Read TLS certificate and private key */
    char *cert_pem = NULL, *key_pem = NULL;
    if (g_config.tls_cert[0] && g_config.tls_key[0]) {
        cert_pem = read_file_to_string(g_config.tls_cert);
        key_pem  = read_file_to_string(g_config.tls_key);
    }

    unsigned int flags = MHD_USE_INTERNAL_POLLING_THREAD;
    if (cert_pem && key_pem) {
        flags |= MHD_USE_TLS;
        api_daemon = MHD_start_daemon(flags, g_config.api_listen_port,
                                      NULL, NULL,
                                      &api_router, NULL,
                                      MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                                      MHD_OPTION_HTTPS_MEM_KEY, key_pem,
                                      MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                      MHD_OPTION_END);
    } else {
        LOG_WARN("TLS cert/key not configured, running plain HTTP (INSECURE!)");
        api_daemon = MHD_start_daemon(flags, g_config.api_listen_port,
                                      NULL, NULL,
                                      &api_router, NULL,
                                      MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                                      MHD_OPTION_END);
    }
    /* Don't free cert_pem/key_pem - MHD needs them for the lifetime of the daemon */

    if (!api_daemon) {
        LOG_ERROR("Failed to start MHD daemon on port %d", g_config.api_listen_port);
        return -1;
    }
    LOG_INFO("API server listening on %s:%d%s",
             g_config.api_listen_addr, g_config.api_listen_port,
             (cert_pem && key_pem) ? " (TLS)" : " (plain HTTP)");
    return 0;
}

void api_stop(void) {
    if (api_daemon) {
        MHD_stop_daemon(api_daemon);
        api_daemon = NULL;
    }
}
