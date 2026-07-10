#ifndef IP_POOL_H
#define IP_POOL_H

#include <stdint.h>

// Initialize IP pool from CIDR and exclude ranges
int ip_pool_init(const char *cidr, const char *exclude);

// Allocate an available IP address from the pool
// Returns 0 on success and copies the IP into out_ip
int ip_pool_allocate(char *out_ip, int max_len);

// Release an IP address back to the pool
int ip_pool_release(const char *ip);

// Mark an IP as used (during db initialization)
int ip_pool_mark_used(const char *ip);

void ip_pool_destroy(void);

#endif // IP_POOL_H
