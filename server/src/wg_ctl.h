#ifndef WG_CTL_H
#define WG_CTL_H

#include <stdint.h>
#include "auth.h" // For WG_KEY_LEN

// Loads static peers from wg0.conf and applies them via netlink (no shell commands)
int wgctl_load_static_config(const char *ifname, const char *conf_path);

// Add a peer dynamically
int wgctl_add_peer(const char *ifname, const uint8_t pubkey[WG_KEY_LEN], const uint8_t psk[WG_KEY_LEN], const char *allowed_ip_cidr);

// Remove a peer
int wgctl_remove_peer(const char *ifname, const uint8_t pubkey[WG_KEY_LEN]);

// Get statistics for a peer
int wgctl_get_peer_stats(const char *ifname, const uint8_t pubkey[WG_KEY_LEN], uint64_t *rx_bytes, uint64_t *tx_bytes, int64_t *last_handshake_time);

// Get the server's WireGuard public key from the kernel interface
int wgctl_get_server_pubkey(const char *ifname, uint8_t pubkey_out[WG_KEY_LEN]);

#endif // WG_CTL_H
