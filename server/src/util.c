#include "util.h"
#include <stdio.h>
#include <stdarg.h>
#include <sodium.h>

static int current_log_level = LOG_LEVEL_INFO;

void set_log_level(int level) {
    current_log_level = level;
}

void vlog(int level, const char *fmt, ...) {
    if (level < current_log_level) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max_len) {
    if (sodium_bin2base64(out, out_max_len, in, in_len, sodium_base64_VARIANT_ORIGINAL) == NULL) {
        return -1;
    }
    return 0;
}

int base64_decode(const char *in, uint8_t *out, size_t out_max_len, size_t *out_len) {
    if (sodium_base642bin(out, out_max_len, in, strlen(in), NULL, out_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        return -1;
    }
    return 0;
}

int base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max_len) {
    if (sodium_bin2base64(out, out_max_len, in, in_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        return -1;
    }
    return 0;
}

void generate_random_bytes(uint8_t *buf, size_t len) {
    randombytes_buf(buf, len);
}
