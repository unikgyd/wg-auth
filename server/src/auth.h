#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stddef.h>

#define WG_KEY_LEN 32

// Verify password using argon2id
int auth_verify_password(const char *hash, const char *password);

// Hash password using argon2id
int auth_hash_password(const char *password, char *hash_out, size_t hash_max_len);

// Generate WireGuard keypair
int auth_generate_keypair(uint8_t public_key[WG_KEY_LEN], uint8_t private_key[WG_KEY_LEN]);

// Generate PresharedKey
void auth_generate_psk(uint8_t psk[WG_KEY_LEN]);

// Generate Session Token
void auth_generate_token(char *token_b64, size_t max_len);

#endif // AUTH_H
