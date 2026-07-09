#include "util.h"
#include "db.h"
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s <db_path> <username> <password>\n", argv[0]);
        printf("Example: %s accounts.db alice password123\n", argv[0]);
        return 1;
    }

    if (sodium_init() < 0) {
        printf("libsodium init failed\n");
        return 1;
    }

    const char *db_path = argv[1];
    const char *username = argv[2];
    const char *password = argv[3];

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
