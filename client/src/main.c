#include "client_api.h"
#include "client_wg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>

#define TOKEN_FILE "/var/run/vpn-client.token"
#define IFNAME "wg-vpn"

static volatile int keep_running = 1;
static char current_token[256] = {0};

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

static void save_token(const char *token) {
    FILE *f = fopen(TOKEN_FILE, "w");
    if (f) {
#ifndef _WIN32
        chmod(TOKEN_FILE, 0600);
#endif
        fprintf(f, "%s", token);
        fclose(f);
    }
}

static void load_token(char *token, size_t size) {
    token[0] = '\0';
    FILE *f = fopen(TOKEN_FILE, "r");
    if (f) {
        if (fgets(token, size, f)) {
            token[strcspn(token, "\r\n")] = 0;
        }
        fclose(f);
    }
}

static void clear_token(void) {
    unlink(TOKEN_FILE);
}

void *renew_thread_func(void *arg) {
    wg_client_config_t *config = (wg_client_config_t *)arg;
    
    while (keep_running) {
        // Sleep for a while, checking keep_running every second
        for (int i = 0; i < 60 && keep_running; i++) {
            sleep(1);
        }
        
        if (!keep_running) break;

        int64_t now = (int64_t)time(NULL);
        // Renew if expiring in less than 15 minutes (900 seconds)
        // Adjust for tests if session ttl is very short
        if (config->expires_at - now < 900) {
            int64_t new_exp = 0;
            if (client_api_renew(current_token, &new_exp) == 0) {
                printf("Session renewed. New expiry: %lld\n", (long long)new_exp);
                config->expires_at = new_exp;
            } else {
                fprintf(stderr, "Failed to renew session. Will try again later.\n");
            }
        }
    }
    return NULL;
}

void print_usage(const char *progname) {
    printf("Usage:\n");
    printf("  %s login <username> <password> [--server <url>] [--insecure]\n", progname);
    printf("  %s status\n", progname);
    printf("  %s logout\n", progname);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *server_url = "https://127.0.0.1:8443";
    int insecure = 0; // Default to secure; use --insecure to override
    
    // Simple arg parsing for server url and insecure flag
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_url = argv[i+1];
        }
        if (strcmp(argv[i], "--insecure") == 0) {
            insecure = 1;
        }
    }

    client_api_init(server_url, NULL, insecure);

    if (strcmp(cmd, "login") == 0) {
        if (argc < 4) {
            printf("Usage: %s login <username> <password>\n", argv[0]);
            return 1;
        }
        const char *username = argv[2];
        const char *password = argv[3];
        // Copy password to stack buffer, then overwrite argv to hide from ps
        char pass_buf[256];
        strncpy(pass_buf, password, sizeof(pass_buf) - 1);
        pass_buf[sizeof(pass_buf) - 1] = '\0';
        memset(argv[3], 0, strlen(argv[3]));  // Overwrite argv to hide from process list
        password = pass_buf;

        wg_client_config_t config;
        printf("Logging in to %s...\n", server_url);
        if (client_api_login(username, password, &config) != 0) {
            fprintf(stderr, "Login failed.\n");
            return 1;
        }

        printf("Login successful! IP: %s, Endpoint: %s\n", config.client_address, config.endpoint);
        strncpy(current_token, config.session_token, sizeof(current_token)-1);
        save_token(current_token);

        printf("Setting up WireGuard interface (%s)...\n", IFNAME);
        if (client_wg_up(IFNAME, &config) != 0) {
            fprintf(stderr, "Failed to bring up WireGuard interface.\n");
            client_api_logout(current_token);
            clear_token();
            return 1;
        }

        signal(SIGINT, handle_sigint);
        signal(SIGTERM, handle_sigint);

        pthread_t renew_thread;
        pthread_create(&renew_thread, NULL, renew_thread_func, &config);

        printf("Tunnel is UP. Press Ctrl+C to disconnect.\n");
        while (keep_running) {
            sleep(1);
        }

        printf("\nDisconnecting...\n");
        pthread_join(renew_thread, NULL);
        client_api_logout(current_token);
        client_wg_down(IFNAME);
        clear_token();
        printf("Disconnected.\n");

    } else if (strcmp(cmd, "status") == 0) {
        load_token(current_token, sizeof(current_token));
        if (current_token[0] == '\0') {
            printf("Not logged in.\n");
            return 1;
        }
        wg_client_status_t stats;
        if (client_api_status(current_token, &stats) == 0) {
            printf("Status: Connected\n");
            printf("RX Bytes: %llu\n", (unsigned long long)stats.rx_bytes);
            printf("TX Bytes: %llu\n", (unsigned long long)stats.tx_bytes);
            printf("Last Handshake: %lld\n", (long long)stats.last_handshake_time);
            printf("Session Expires At: %lld\n", (long long)stats.expires_at);
        } else {
            printf("Failed to get status. Session might be expired.\n");
        }
    } else if (strcmp(cmd, "logout") == 0) {
        load_token(current_token, sizeof(current_token));
        if (current_token[0] != '\0') {
            printf("Logging out from server...\n");
            client_api_logout(current_token);
            clear_token();
        }
        printf("Bringing down local interface...\n");
        client_wg_down(IFNAME);
        printf("Done.\n");
    } else {
        print_usage(argv[0]);
        return 1;
    }

    client_api_cleanup();
    return 0;
}
