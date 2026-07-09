#include "reaper.h"
#include "config.h"
#include "db.h"
#include "ip_pool.h"
#include "wg_ctl.h"
#include "util.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_t reaper_thread;
static volatile int stop_flag = 0;

static void* reaper_worker(void* arg) {
    (void)arg;
    while (!stop_flag) {
        session_t *expired_sessions;
        int count = 0;
        
        if (db_get_expired_sessions(&expired_sessions, &count) == 0 && count > 0) {
            for (int i = 0; i < count; i++) {
                session_t *sess = &expired_sessions[i];
                LOG_INFO("Reaping expired session for account %d, IP %s", sess->account_id, sess->allowed_ip);
                
                uint8_t pubkey[32];
                size_t out_len;
                if (base64_decode(sess->device_pubkey, pubkey, sizeof(pubkey), &out_len) == 0) {
                    wgctl_remove_peer(g_config.wg_interface, pubkey);
                }
                
                ip_pool_release(sess->allowed_ip);
                db_revoke_session(sess->id);
                db_log_audit(sess->account_id, "expired", sess->allowed_ip);
            }
            free(expired_sessions);
        }
        
        for (int i = 0; i < g_config.session_reap_interval_seconds && !stop_flag; i++) {
#ifdef _WIN32
            Sleep(1000);
#else
            sleep(1);
#endif
        }
    }
    return NULL;
}

int reaper_start(void) {
    stop_flag = 0;
    if (pthread_create(&reaper_thread, NULL, reaper_worker, NULL) != 0) {
        LOG_ERROR("Failed to start reaper thread");
        return -1;
    }
    return 0;
}

void reaper_stop(void) {
    stop_flag = 1;
    pthread_join(reaper_thread, NULL);
}
