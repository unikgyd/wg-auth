#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3

void set_log_level(int level);
void vlog(int level, const char *fmt, ...);

#define LOG_DEBUG(fmt, ...) vlog(LOG_LEVEL_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  vlog(LOG_LEVEL_INFO,  "[INFO]  " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  vlog(LOG_LEVEL_WARN,  "[WARN]  " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) vlog(LOG_LEVEL_ERROR, "[ERROR] " fmt, ##__VA_ARGS__)

// Base64 encode/decode using libsodium
int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max_len);
int base64_decode(const char *in, uint8_t *out, size_t out_max_len, size_t *out_len);
int base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max_len);

// Generate random bytes using libsodium
void generate_random_bytes(uint8_t *buf, size_t len);

#endif // UTIL_H
