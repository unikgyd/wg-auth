#ifndef DB_H
#define DB_H

#include <stdint.h>
#include <sqlite3.h>

typedef struct {
    int id;
    char username[64];
    char password_hash[256];
    int64_t created_at;
    int disabled;
} account_t;

typedef struct {
    int id;
    int account_id;
    char device_pubkey[64];
    char allowed_ip[32];
    char session_token[64];
    int64_t created_at;
    int64_t expires_at;
    int revoked;
    int64_t last_seen_at;
} session_t;

int db_init(const char *db_path);
void db_close(void);

// Account operations
int db_get_account_by_username(const char *username, account_t *acc);
int db_create_account(const char *username, const char *password_hash);

// Session operations
int db_create_session(int account_id, const char *pubkey, const char *allowed_ip, const char *token, int64_t expires_at);
int db_get_session_by_token(const char *token, session_t *sess);
int db_revoke_session(int session_id);
int db_update_session_expiry(int session_id, int64_t expires_at);
int db_get_expired_sessions(session_t **sessions, int *count);
int db_get_active_sessions(session_t **sessions, int *count);

// Audit
int db_log_audit(int account_id, const char *action, const char *detail);

// Session utilities
int db_count_active_sessions(int account_id);
void db_revoke_all_active_sessions(void);

#endif // DB_H
