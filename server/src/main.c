#include "util.h"
#include "config.h"
#include "db.h"
#include "auth.h"
#include "ip_pool.h"
#include "wg_ctl.h"
#include "api_handlers.h"
#include "reaper.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sodium.h>

static volatile int keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

/* Restore IP pool and WireGuard peers for sessions that survived a restart */
static void recover_active_sessions(void) {
    session_t *sessions = NULL;
    int count = 0;
    
    if (db_get_active_sessions(&sessions, &count) != 0 || count == 0) {
        if (sessions) free(sessions);
        LOG_INFO("No active sessions to recover");
        return;
    }
    
    LOG_INFO("Recovering %d active session(s) from database...", count);
    for (int i = 0; i < count; i++) {
        session_t *sess = &sessions[i];
        
        /* Mark the IP as used in the pool */
        ip_pool_mark_used(sess->allowed_ip);
        
        /* Re-inject the peer into the WireGuard kernel interface */
        uint8_t pubkey[WG_KEY_LEN];
        size_t out_len;
        if (base64_decode(sess->device_pubkey, pubkey, sizeof(pubkey), &out_len) == 0 &&
            out_len == WG_KEY_LEN) {
            wgctl_add_peer(g_config.wg_interface, pubkey, NULL, sess->allowed_ip);
            LOG_DEBUG("Recovered peer for account %d, IP %s", sess->account_id, sess->allowed_ip);
        }
    }
    free(sessions);
    LOG_INFO("Session recovery complete");
}

int main(int argc, char **argv) {
    set_log_level(LOG_LEVEL_INFO);
    
    if (sodium_init() < 0) {
        LOG_ERROR("libsodium initialization failed");
        return 1;
    }
    
    const char *conf_path = (argc > 1) ? argv[1] : "/etc/vpn-authd/authd.conf";
    if (load_config(conf_path) != 0) {
        LOG_WARN("Could not load config file %s, proceeding with defaults", conf_path);
    }
    
    if (db_init(g_config.db_path[0] ? g_config.db_path : "accounts.db") != 0) {
        LOG_ERROR("Failed to initialize database");
        return 1;
    }
    
    if (ip_pool_init(g_config.ip_pool_cidr[0] ? g_config.ip_pool_cidr : "10.8.1.0/23", g_config.ip_pool_exclude) != 0) {
        LOG_ERROR("Failed to initialize IP pool");
        return 1;
    }
    
    LOG_INFO("IP pool initialized");
    
    wgctl_load_static_config(g_config.wg_interface, g_config.wg_conf_path);
    
    /* Restore active sessions from DB into IP pool and WireGuard kernel */
    recover_active_sessions();
    
    if (api_start() != 0) {
        LOG_ERROR("Failed to start API");
        return 1;
    }
    
    if (reaper_start() != 0) {
        LOG_ERROR("Failed to start Reaper");
        return 1;
    }
    
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    
    LOG_INFO("vpn-authd is running. Press Ctrl+C to stop.");
    while (keep_running) {
        sleep(1);
    }
    
    LOG_INFO("Shutting down...");
    reaper_stop();
    api_stop();
    db_close();
    
    return 0;
}

