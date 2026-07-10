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

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

/* Revoke all active sessions on startup - clients will need to re-login.
 * This is safer than recovering without PresharedKeys (S-M10). */
static void revoke_stale_sessions(void) {
    LOG_INFO("Revoking all active sessions (server restart)");
    db_revoke_all_active_sessions();
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
    
    if (db_init(g_config.db_path[0] ? g_config.db_path : "/var/lib/vpn-authd/accounts.db") != 0) {
        LOG_ERROR("Failed to initialize database");
        return 1;
    }
    
    if (ip_pool_init(g_config.ip_pool_cidr[0] ? g_config.ip_pool_cidr : "10.8.1.0/23", g_config.ip_pool_exclude) != 0) {
        LOG_ERROR("Failed to initialize IP pool");
        return 1;
    }
    
    LOG_INFO("IP pool initialized");
    
    wgctl_load_static_config(g_config.wg_interface, g_config.wg_conf_path);
    
    /* Revoke stale sessions rather than recovering without PresharedKeys */
    revoke_stale_sessions();
    
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
    ip_pool_destroy();
    
    return 0;
}

