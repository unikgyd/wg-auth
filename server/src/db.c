#include "db.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *db = NULL;

static int exec_sql(const char *sql) {
    char *err_msg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("SQL error: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

int db_init(const char *db_path) {
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
        LOG_ERROR("Cannot open database: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    const char *sql_accounts = 
        "CREATE TABLE IF NOT EXISTS accounts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "created_at INTEGER NOT NULL, "
        "disabled INTEGER NOT NULL DEFAULT 0);";

    const char *sql_sessions = 
        "CREATE TABLE IF NOT EXISTS sessions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "account_id INTEGER NOT NULL REFERENCES accounts(id), "
        "device_pubkey TEXT NOT NULL, "
        "allowed_ip TEXT NOT NULL, "
        "session_token TEXT UNIQUE NOT NULL, "
        "created_at INTEGER NOT NULL, "
        "expires_at INTEGER NOT NULL, "
        "revoked INTEGER NOT NULL DEFAULT 0, "
        "last_seen_at INTEGER);";

    const char *sql_audit = 
        "CREATE TABLE IF NOT EXISTS audit_log ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "account_id INTEGER, "
        "action TEXT NOT NULL, "
        "detail TEXT, "
        "created_at INTEGER NOT NULL);";

    if (exec_sql(sql_accounts) != 0) return -1;
    if (exec_sql(sql_sessions) != 0) return -1;
    if (exec_sql(sql_audit) != 0) return -1;

    exec_sql("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);");
    exec_sql("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);");

    return 0;
}

void db_close(void) {
    if (db) sqlite3_close(db);
}

int db_get_account_by_username(const char *username, account_t *acc) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT id, username, password_hash, created_at, disabled FROM accounts WHERE username = ?", -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        acc->id = sqlite3_column_int(stmt, 0);
        strncpy(acc->username, (const char*)sqlite3_column_text(stmt, 1), sizeof(acc->username)-1);
        strncpy(acc->password_hash, (const char*)sqlite3_column_text(stmt, 2), sizeof(acc->password_hash)-1);
        acc->created_at = sqlite3_column_int64(stmt, 3);
        acc->disabled = sqlite3_column_int(stmt, 4);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

int db_create_account(const char *username, const char *password_hash) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO accounts (username, password_hash, created_at, disabled) VALUES (?, ?, ?, 0)", -1, &stmt, NULL) != SQLITE_OK) return -1;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, time(NULL));
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_create_session(int account_id, const char *pubkey, const char *allowed_ip, const char *token, int64_t expires_at) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO sessions (account_id, device_pubkey, allowed_ip, session_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) return -1;
    
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_text(stmt, 2, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, allowed_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, time(NULL));
    sqlite3_bind_int64(stmt, 6, expires_at);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_get_session_by_token(const char *token, session_t *sess) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT id, account_id, device_pubkey, allowed_ip, session_token, created_at, expires_at, revoked, last_seen_at FROM sessions WHERE session_token = ?", -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        sess->id = sqlite3_column_int(stmt, 0);
        sess->account_id = sqlite3_column_int(stmt, 1);
        strncpy(sess->device_pubkey, (const char*)sqlite3_column_text(stmt, 2), sizeof(sess->device_pubkey)-1);
        strncpy(sess->allowed_ip, (const char*)sqlite3_column_text(stmt, 3), sizeof(sess->allowed_ip)-1);
        strncpy(sess->session_token, (const char*)sqlite3_column_text(stmt, 4), sizeof(sess->session_token)-1);
        sess->created_at = sqlite3_column_int64(stmt, 5);
        sess->expires_at = sqlite3_column_int64(stmt, 6);
        sess->revoked = sqlite3_column_int(stmt, 7);
        sess->last_seen_at = sqlite3_column_int64(stmt, 8);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

int db_revoke_session(int session_id) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "UPDATE sessions SET revoked = 1 WHERE id = ?", -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, session_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_update_session_expiry(int session_id, int64_t expires_at) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "UPDATE sessions SET expires_at = ? WHERE id = ?", -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, expires_at);
    sqlite3_bind_int(stmt, 2, session_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_get_expired_sessions(session_t **sessions, int *count) {
    *count = 0;
    *sessions = NULL;
    
    int capacity = 64;
    session_t *buf = malloc(sizeof(session_t) * capacity);
    if (!buf) return -1;
    
    sqlite3_stmt *stmt;
    int64_t now = time(NULL);
    if (sqlite3_prepare_v2(db, "SELECT id, account_id, device_pubkey, allowed_ip, session_token FROM sessions WHERE revoked = 0 AND expires_at < ? LIMIT 100", -1, &stmt, NULL) != SQLITE_OK) {
        free(buf);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            session_t *tmp = realloc(buf, sizeof(session_t) * capacity);
            if (!tmp) break;
            buf = tmp;
        }
        session_t *s = &buf[*count];
        memset(s, 0, sizeof(session_t));
        s->id = sqlite3_column_int(stmt, 0);
        s->account_id = sqlite3_column_int(stmt, 1);
        strncpy(s->device_pubkey, (const char*)sqlite3_column_text(stmt, 2), sizeof(s->device_pubkey)-1);
        strncpy(s->allowed_ip, (const char*)sqlite3_column_text(stmt, 3), sizeof(s->allowed_ip)-1);
        strncpy(s->session_token, (const char*)sqlite3_column_text(stmt, 4), sizeof(s->session_token)-1);
        (*count)++;
    }
    sqlite3_finalize(stmt);
    *sessions = buf;
    return 0;
}

int db_get_active_sessions(session_t **sessions, int *count) {
    *count = 0;
    *sessions = NULL;
    
    int capacity = 64;
    session_t *buf = malloc(sizeof(session_t) * capacity);
    if (!buf) return -1;
    
    sqlite3_stmt *stmt;
    int64_t now = time(NULL);
    if (sqlite3_prepare_v2(db, "SELECT id, account_id, device_pubkey, allowed_ip, session_token FROM sessions WHERE revoked = 0 AND expires_at >= ?", -1, &stmt, NULL) != SQLITE_OK) {
        free(buf);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            session_t *tmp = realloc(buf, sizeof(session_t) * capacity);
            if (!tmp) break;
            buf = tmp;
        }
        session_t *s = &buf[*count];
        memset(s, 0, sizeof(session_t));
        s->id = sqlite3_column_int(stmt, 0);
        s->account_id = sqlite3_column_int(stmt, 1);
        strncpy(s->device_pubkey, (const char*)sqlite3_column_text(stmt, 2), sizeof(s->device_pubkey)-1);
        strncpy(s->allowed_ip, (const char*)sqlite3_column_text(stmt, 3), sizeof(s->allowed_ip)-1);
        strncpy(s->session_token, (const char*)sqlite3_column_text(stmt, 4), sizeof(s->session_token)-1);
        (*count)++;
    }
    sqlite3_finalize(stmt);
    *sessions = buf;
    return 0;
}

int db_log_audit(int account_id, const char *action, const char *detail) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO audit_log (account_id, action, detail, created_at) VALUES (?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_text(stmt, 2, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, detail, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, time(NULL));
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
