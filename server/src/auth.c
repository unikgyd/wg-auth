#include "auth.h"
#include "config.h"
#include "util.h"
#include <sodium.h>
#include <string.h>

int auth_verify_password(const char *hash, const char *password) {
    if (crypto_pwhash_str_verify(hash, password, strlen(password)) != 0) {
        return -1;
    }
    return 0;
}

int auth_hash_password(const char *password, char *hash_out, size_t hash_max_len) {
    if (hash_max_len < crypto_pwhash_STRBYTES) return -1;
    unsigned long long opslimit = g_config.argon2_time_cost > 0 ? (unsigned long long)g_config.argon2_time_cost : crypto_pwhash_OPSLIMIT_INTERACTIVE;
    size_t memlimit = g_config.argon2_mem_cost_kb > 0 ? (size_t)g_config.argon2_mem_cost_kb * 1024 : crypto_pwhash_MEMLIMIT_INTERACTIVE;
    if (crypto_pwhash_str(hash_out, password, strlen(password), opslimit, memlimit) != 0) {
        return -1;
    }
    return 0;
}

int auth_generate_keypair(uint8_t public_key[WG_KEY_LEN], uint8_t private_key[WG_KEY_LEN]) {
    // Generate private key (X25519)
    randombytes_buf(private_key, WG_KEY_LEN);
    // RFC7748 curve25519 clamping
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    
    // Derive public key
    if (crypto_scalarmult_base(public_key, private_key) != 0) {
        return -1;
    }
    return 0;
}

void auth_generate_psk(uint8_t psk[WG_KEY_LEN]) {
    randombytes_buf(psk, WG_KEY_LEN);
}

void auth_generate_token(char *token_b64, size_t max_len) {
    uint8_t raw[32];
    randombytes_buf(raw, sizeof(raw));
    base64url_encode(raw, sizeof(raw), token_b64, max_len);
}
