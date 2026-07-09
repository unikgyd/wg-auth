#include "client_wg.h"
#include "wireguard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

static int resolve_endpoint(const char *endpoint_str, wg_endpoint *endpoint) {
    char host[256];
    strncpy(host, endpoint_str, sizeof(host)-1);
    host[sizeof(host)-1] = '\0';

    char *colon = strrchr(host, ':');
    if (!colon) return -1;
    *colon = '\0';
    int port = atoi(colon + 1);

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;

    memset(endpoint, 0, sizeof(wg_endpoint));
    if (res->ai_family == AF_INET) {
        endpoint->addr4 = *(struct sockaddr_in *)res->ai_addr;
        endpoint->addr4.sin_port = htons(port);
    } else if (res->ai_family == AF_INET6) {
        endpoint->addr6 = *(struct sockaddr_in6 *)res->ai_addr;
        endpoint->addr6.sin6_port = htons(port);
    } else {
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return 0;
}

static int parse_allowed_ip(const char *cidr, wg_allowedip *aip) {
    char ip_str[64];
    strncpy(ip_str, cidr, sizeof(ip_str)-1);
    ip_str[sizeof(ip_str)-1] = '\0';
    
    char *slash = strchr(ip_str, '/');
    int mask = 32;
    if (slash) {
        *slash = '\0';
        mask = atoi(slash + 1);
    }

    memset(aip, 0, sizeof(wg_allowedip));
    if (inet_pton(AF_INET, ip_str, &aip->ip4) == 1) {
        aip->family = AF_INET;
        aip->cidr = mask;
        return 0;
    } else if (inet_pton(AF_INET6, ip_str, &aip->ip6) == 1) {
        aip->family = AF_INET6;
        aip->cidr = slash ? mask : 128;
        return 0;
    }
    return -1;
}

int client_wg_up(const char *ifname, const wg_client_config_t *config) {
    // 1. Create the device
    wg_del_device(ifname); // Ensure it's clean
    if (wg_add_device(ifname) != 0) {
        perror("wg_add_device");
        return -1;
    }

    // 2. Configure WireGuard device and peers
    wg_device dev = {0};
    strncpy(dev.name, ifname, IFNAMSIZ - 1);
    dev.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_REPLACE_PEERS;
    
    if (wg_key_from_base64(dev.private_key, config->client_private_key_b64) != 0) {
        fprintf(stderr, "Invalid client private key\n");
        return -1;
    }

    wg_peer peer = {0};
    peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS | WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
    peer.persistent_keepalive_interval = 25;

    if (wg_key_from_base64(peer.public_key, config->server_public_key_b64) != 0) {
        fprintf(stderr, "Invalid server public key\n");
        return -1;
    }

    if (config->preshared_key_b64[0] != '\0') {
        if (wg_key_from_base64(peer.preshared_key, config->preshared_key_b64) == 0) {
            peer.flags |= WGPEER_HAS_PRESHARED_KEY;
        }
    }

    if (resolve_endpoint(config->endpoint, &peer.endpoint) != 0) {
        fprintf(stderr, "Failed to resolve endpoint %s\n", config->endpoint);
        return -1;
    }

    // Parse AllowedIPs (can be comma separated)
    char allowed_ips_copy[256];
    strncpy(allowed_ips_copy, config->allowed_ips, sizeof(allowed_ips_copy)-1);
    allowed_ips_copy[sizeof(allowed_ips_copy)-1] = '\0';

    wg_allowedip *first_aip = NULL;
    wg_allowedip *last_aip = NULL;
    char *token = strtok(allowed_ips_copy, ", ");
    while (token) {
        wg_allowedip *aip = calloc(1, sizeof(wg_allowedip));
        if (parse_allowed_ip(token, aip) == 0) {
            if (!first_aip) {
                first_aip = aip;
            } else {
                last_aip->next_allowedip = aip;
            }
            last_aip = aip;
        } else {
            free(aip);
        }
        token = strtok(NULL, ", ");
    }

    peer.first_allowedip = first_aip;
    peer.last_allowedip = last_aip;

    dev.first_peer = &peer;
    dev.last_peer = &peer;

    if (wg_set_device(&dev) != 0) {
        perror("wg_set_device");
        return -1;
    }

    // Free AllowedIPs
    wg_allowedip *curr = first_aip;
    while (curr) {
        wg_allowedip *next = curr->next_allowedip;
        free(curr);
        curr = next;
    }

    // 3. Bring the interface up and set IP
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link set up dev %s", ifname);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to bring up interface %s\n", ifname);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", config->client_address, ifname);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to assign IP %s to %s\n", config->client_address, ifname);
        return -1;
    }

    // Add route for AllowedIPs if they are not 0.0.0.0/0 (which would need more complex default route logic)
    strncpy(allowed_ips_copy, config->allowed_ips, sizeof(allowed_ips_copy)-1);
    token = strtok(allowed_ips_copy, ", ");
    while (token) {
        // Simple heuristic: if it's not the default route, add it directly to the dev
        if (strcmp(token, "0.0.0.0/0") != 0 && strcmp(token, "::/0") != 0) {
            snprintf(cmd, sizeof(cmd), "ip route add %s dev %s 2>/dev/null", token, ifname);
            system(cmd); // Ignore errors, it might already be in the table
        }
        token = strtok(NULL, ", ");
    }

    return 0;
}

int client_wg_down(const char *ifname) {
    char cmd[512];
    // Delete the interface
    snprintf(cmd, sizeof(cmd), "ip link del dev %s 2>/dev/null", ifname);
    system(cmd);
    
    // Also use wg API just in case
    wg_del_device(ifname);
    return 0;
}
