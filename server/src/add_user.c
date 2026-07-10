#include "util.h"
#include "db.h"
#include "auth.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <username> [--db <db_path>]\n", argv[0]);
        return 1;
    }

    const char *username = NULL;
    const char *db_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[i + 1];
            i++;
        } else if (!username) {
            username = argv[i];
        } else {
            printf("Usage: %s <username> [--db <db_path>]\n", argv[0]);
            return 1;
        }
    }

    if (!username) {
        printf("Usage: %s <username> [--db <db_path>]\n", argv[0]);
        return 1;
    }

    if (!db_path) {
        // Try loading config file to get db path
        load_config("/etc/vpn-authd/authd.conf");
        db_path = g_config.db_path[0] ? g_config.db_path : "/var/lib/vpn-authd/accounts.db";
    }

    if (sodium_init() < 0) {
        printf("libsodium init failed\n");
        return 1;
    }

    char *password = getpass("Password: ");
    if (!password || strlen(password) == 0) {
        printf("Error: Password cannot be empty\n");
        return 1;
    }

    // 初始化数据库连接（如果表不存在会自动建表）
    if (db_init(db_path) != 0) {
        printf("Failed to open or initialize db: %s\n", db_path);
        return 1;
    }

    char hash[crypto_pwhash_STRBYTES];
    if (auth_hash_password(password, hash, sizeof(hash)) != 0) {
        printf("Failed to hash password\n");
        db_close();
        return 1;
    }

    if (db_create_account(username, hash) != 0) {
        printf("Failed to create account (maybe username '%s' already exists?)\n", username);
        db_close();
        return 1;
    }

    printf("Account '%s' created successfully in '%s'!\n", username, db_path);
    db_close();
    return 0;
}
