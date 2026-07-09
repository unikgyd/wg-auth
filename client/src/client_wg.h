#ifndef CLIENT_WG_H
#define CLIENT_WG_H

#include "client_api.h"

// Bring up the WireGuard tunnel using the provided config
// This will create the interface, set keys/peers, assign IP, and add routes.
int client_wg_up(const char *ifname, const wg_client_config_t *config);

// Tear down the WireGuard tunnel
int client_wg_down(const char *ifname);

#endif // CLIENT_WG_H
