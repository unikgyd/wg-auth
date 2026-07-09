#include "client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

static char g_server_url[256];
static char g_ca_cert_path[256];
static int g_insecure = 0;

struct memory_struct {
    char *memory;
    size_t size;
};

static size_t write_memory_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct memory_struct *mem = (struct memory_struct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int client_api_init(const char *server_url, const char *ca_cert_path, int insecure) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    snprintf(g_server_url, sizeof(g_server_url), "%s", server_url);
    if (ca_cert_path && ca_cert_path[0] != '\0') {
        snprintf(g_ca_cert_path, sizeof(g_ca_cert_path), "%s", ca_cert_path);
    } else {
        g_ca_cert_path[0] = '\0';
    }
    g_insecure = insecure;
    return 0;
}

void client_api_cleanup(void) {
    curl_global_cleanup();
}

static cJSON* do_post(const char *endpoint, const char *json_body, const char *auth_token) {
    CURL *curl;
    CURLcode res;
    struct memory_struct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    cJSON *response_json = NULL;

    curl = curl_easy_init();
    if (!curl) {
        free(chunk.memory);
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "%s%s", g_server_url, endpoint);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (auth_token) {
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", auth_token);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (json_body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    if (g_insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else if (g_ca_cert_path[0] != '\0') {
        curl_easy_setopt(curl, CURLOPT_CAINFO, g_ca_cert_path);
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200 && chunk.size > 0) {
            response_json = cJSON_Parse(chunk.memory);
        } else {
            fprintf(stderr, "HTTP Request failed with code: %ld\nResponse: %s\n", http_code, chunk.memory);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.memory);

    return response_json;
}

static cJSON* do_get(const char *endpoint, const char *auth_token) {
    CURL *curl;
    CURLcode res;
    struct memory_struct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    cJSON *response_json = NULL;

    curl = curl_easy_init();
    if (!curl) {
        free(chunk.memory);
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "%s%s", g_server_url, endpoint);

    struct curl_slist *headers = NULL;
    if (auth_token) {
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", auth_token);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    if (g_insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else if (g_ca_cert_path[0] != '\0') {
        curl_easy_setopt(curl, CURLOPT_CAINFO, g_ca_cert_path);
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200 && chunk.size > 0) {
            response_json = cJSON_Parse(chunk.memory);
        } else {
            fprintf(stderr, "HTTP Request failed with code: %ld\nResponse: %s\n", http_code, chunk.memory);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.memory);

    return response_json;
}

static void copy_string_field(cJSON *obj, const char *key, char *dest, size_t dest_size) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(item) && (item->valuestring != NULL)) {
        snprintf(dest, dest_size, "%s", item->valuestring);
    } else {
        dest[0] = '\0';
    }
}

int client_api_login(const char *username, const char *password, wg_client_config_t *out_config) {
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "username", username);
    cJSON_AddStringToObject(req, "password", password);
    char *req_str = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);

    cJSON *resp = do_post("/login", req_str, NULL);
    free(req_str);

    if (!resp) return -1;

    memset(out_config, 0, sizeof(wg_client_config_t));
    copy_string_field(resp, "session_token", out_config->session_token, sizeof(out_config->session_token));
    copy_string_field(resp, "client_private_key", out_config->client_private_key_b64, sizeof(out_config->client_private_key_b64));
    copy_string_field(resp, "client_address", out_config->client_address, sizeof(out_config->client_address));
    copy_string_field(resp, "server_public_key", out_config->server_public_key_b64, sizeof(out_config->server_public_key_b64));
    copy_string_field(resp, "preshared_key", out_config->preshared_key_b64, sizeof(out_config->preshared_key_b64));
    copy_string_field(resp, "endpoint", out_config->endpoint, sizeof(out_config->endpoint));
    copy_string_field(resp, "allowed_ips", out_config->allowed_ips, sizeof(out_config->allowed_ips));
    copy_string_field(resp, "dns", out_config->dns, sizeof(out_config->dns));

    cJSON *exp = cJSON_GetObjectItemCaseSensitive(resp, "expires_at");
    if (cJSON_IsNumber(exp)) {
        out_config->expires_at = (int64_t)exp->valuedouble;
    }

    cJSON_Delete(resp);
    
    if (out_config->session_token[0] == '\0') {
        return -1; // Login failed
    }
    return 0;
}

int client_api_logout(const char *session_token) {
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "session_token", session_token);
    char *req_str = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);

    cJSON *resp = do_post("/logout", req_str, session_token);
    free(req_str);

    if (!resp) return -1;
    cJSON_Delete(resp);
    return 0;
}

int client_api_renew(const char *session_token, int64_t *out_new_expiry) {
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "session_token", session_token);
    char *req_str = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);

    cJSON *resp = do_post("/renew", req_str, session_token);
    free(req_str);

    if (!resp) return -1;

    cJSON *exp = cJSON_GetObjectItemCaseSensitive(resp, "expires_at");
    if (cJSON_IsNumber(exp) && out_new_expiry) {
        *out_new_expiry = (int64_t)exp->valuedouble;
    }

    cJSON_Delete(resp);
    return 0;
}

int client_api_status(const char *session_token, wg_client_status_t *out_stats) {
    cJSON *resp = do_get("/status", session_token);
    if (!resp) return -1;

    cJSON *rx = cJSON_GetObjectItemCaseSensitive(resp, "rx_bytes");
    cJSON *tx = cJSON_GetObjectItemCaseSensitive(resp, "tx_bytes");
    cJSON *lh = cJSON_GetObjectItemCaseSensitive(resp, "last_handshake_time");
    cJSON *exp = cJSON_GetObjectItemCaseSensitive(resp, "expires_at");

    if (out_stats) {
        out_stats->rx_bytes = cJSON_IsNumber(rx) ? (uint64_t)rx->valuedouble : 0;
        out_stats->tx_bytes = cJSON_IsNumber(tx) ? (uint64_t)tx->valuedouble : 0;
        out_stats->last_handshake_time = cJSON_IsNumber(lh) ? (int64_t)lh->valuedouble : 0;
        out_stats->expires_at = cJSON_IsNumber(exp) ? (int64_t)exp->valuedouble : 0;
    }

    cJSON_Delete(resp);
    return 0;
}
