#include "wg_ctl.h"
#include "util.h"
#include "wireguard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

/* --------------- helpers --------------- */

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Strip inline comment introduced by ';' (not inside a value we care about). */
static void strip_inline_comment(char *s) {
    char *p = strchr(s, ';');
    if (p) *p = '\0';
}

static int parse_allowed_ip(const char *cidr, wg_allowedip *allowed) {
    char ip_str[64];
    strncpy(ip_str, cidr, sizeof(ip_str)-1);
    ip_str[sizeof(ip_str)-1] = '\0';
    char *slash = strchr(ip_str, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    if (strchr(ip_str, ':')) {
        allowed->family = AF_INET6;
        if (inet_pton(AF_INET6, ip_str, &allowed->ip6) != 1) return -1;
    } else {
        allowed->family = AF_INET;
        if (inet_pton(AF_INET, ip_str, &allowed->ip4) != 1) return -1;
    }
    allowed->cidr = prefix;
    allowed->next_allowedip = NULL;
    return 0;
}

/* --------------- conf file parser --------------- */

enum parse_state { STATE_NONE, STATE_INTERFACE, STATE_PEER };

/*
 * Parse the wg conf file (INI-like format produced by `wg showconf`) and apply
 * the full device configuration via the embeddable-wg-library netlink API.
 *
 * Supported keys:
 *   [Interface]  PrivateKey, ListenPort
 *   [Peer]       PublicKey, PresharedKey, AllowedIPs
 */
int wgctl_load_static_config(const char *ifname, const char *conf_path) {
    FILE *fp = fopen(conf_path, "r");
    if (!fp) {
        LOG_ERROR("wgctl_load_static_config: cannot open %s", conf_path);
        return -1;
    }

    wg_device dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, ifname, sizeof(dev.name) - 1);

    /* Peer chain we are building. */
    wg_peer *first_peer = NULL;
    wg_peer *last_peer  = NULL;
    wg_peer *cur_peer   = NULL;

    enum parse_state state = STATE_NONE;
    char line[1024];
    char interface_address[64] = {0};

    while (fgets(line, sizeof(line), fp)) {
        /* Strip newline */
        line[strcspn(line, "\r\n")] = '\0';

        /* Skip full-line comments */
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';')
            continue;

        /* Section headers */
        if (*p == '[') {
            if (strncasecmp(p, "[Interface]", 11) == 0) {
                state = STATE_INTERFACE;
            } else if (strncasecmp(p, "[Peer]", 6) == 0) {
                state = STATE_PEER;
                cur_peer = calloc(1, sizeof(wg_peer));
                if (!cur_peer) { fclose(fp); goto oom; }
                cur_peer->flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
                /* Append to linked list */
                if (!first_peer) {
                    first_peer = cur_peer;
                } else {
                    last_peer->next_peer = cur_peer;
                }
                last_peer = cur_peer;
            }
            continue;
        }

        /* Key = Value lines */
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);
        strip_inline_comment(val);
        val = trim(val);   /* re-trim after stripping comment */

        if (state == STATE_INTERFACE) {
            if (strcasecmp(key, "PrivateKey") == 0) {
                size_t decoded_len = 0;
                if (base64_decode(val, dev.private_key, WG_KEY_LEN, &decoded_len) != 0 ||
                    decoded_len != WG_KEY_LEN) {
                    LOG_ERROR("wgctl_load_static_config: bad PrivateKey base64");
                    fclose(fp);
                    goto cleanup;
                }
                dev.flags |= WGDEVICE_HAS_PRIVATE_KEY;
            } else if (strcasecmp(key, "ListenPort") == 0) {
                dev.listen_port = (uint16_t)atoi(val);
                dev.flags |= WGDEVICE_HAS_LISTEN_PORT;
            } else if (strcasecmp(key, "Address") == 0) {
                strncpy(interface_address, val, sizeof(interface_address) - 1);
            }
        } else if (state == STATE_PEER && cur_peer) {
            if (strcasecmp(key, "PublicKey") == 0) {
                size_t decoded_len = 0;
                if (base64_decode(val, cur_peer->public_key, WG_KEY_LEN, &decoded_len) != 0 ||
                    decoded_len != WG_KEY_LEN) {
                    LOG_ERROR("wgctl_load_static_config: bad peer PublicKey base64");
                    fclose(fp);
                    goto cleanup;
                }
            } else if (strcasecmp(key, "PresharedKey") == 0) {
                size_t decoded_len = 0;
                if (base64_decode(val, cur_peer->preshared_key, WG_KEY_LEN, &decoded_len) != 0 ||
                    decoded_len != WG_KEY_LEN) {
                    LOG_ERROR("wgctl_load_static_config: bad peer PresharedKey base64");
                    fclose(fp);
                    goto cleanup;
                }
                cur_peer->flags |= WGPEER_HAS_PRESHARED_KEY;
            } else if (strcasecmp(key, "AllowedIPs") == 0) {
                /* Comma-separated list of CIDRs, e.g. "10.8.0.2/32, fd00::2/128" */
                char *saveptr = NULL;
                char *token = strtok_r(val, ",", &saveptr);
                while (token) {
                    token = trim(token);
                    if (*token == '\0') { token = strtok_r(NULL, ",", &saveptr); continue; }

                    wg_allowedip *aip = calloc(1, sizeof(wg_allowedip));
                    if (!aip) { fclose(fp); goto oom; }

                    if (parse_allowed_ip(token, aip) != 0) {
                        LOG_WARN("wgctl_load_static_config: skipping bad AllowedIP: %s", token);
                        free(aip);
                    } else {
                        /* Append to this peer's allowedip list */
                        if (!cur_peer->first_allowedip) {
                            cur_peer->first_allowedip = aip;
                        } else {
                            cur_peer->last_allowedip->next_allowedip = aip;
                        }
                        cur_peer->last_allowedip = aip;
                    }
                    token = strtok_r(NULL, ",", &saveptr);
                }
            }
        }
    }
    fclose(fp);

    /* Wire the peer chain into the device */
    dev.first_peer = first_peer;
    dev.last_peer  = last_peer;

    /* Ensure the device exists before configuring it */
    wg_add_device(dev.name);

    int rc = wg_set_device(&dev);
    if (rc < 0) {
        LOG_ERROR("wgctl_load_static_config: wg_set_device failed (%d)", rc);
        goto cleanup;
    }

    if (interface_address[0] != '\0') {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s 2>/dev/null", interface_address, dev.name);
        system(cmd);
    }
    
    char cmd_up[128];
    snprintf(cmd_up, sizeof(cmd_up), "ip link set up dev %s 2>/dev/null", dev.name);
    system(cmd_up);

    LOG_INFO("wgctl_load_static_config: applied %s via netlink", conf_path);

    /* Fall through to cleanup on success */
cleanup:
    /* Free dynamically-allocated peers and their allowedips */
    {
        wg_peer *peer = first_peer;
        while (peer) {
            wg_allowedip *aip = peer->first_allowedip;
            while (aip) {
                wg_allowedip *next_aip = aip->next_allowedip;
                free(aip);
                aip = next_aip;
            }
            wg_peer *next_peer = peer->next_peer;
            free(peer);
            peer = next_peer;
        }
    }
    return rc < 0 ? -1 : 0;

oom:
    LOG_ERROR("wgctl_load_static_config: out of memory");
    /* Free anything already allocated */
    {
        wg_peer *peer = first_peer;
        while (peer) {
            wg_allowedip *aip = peer->first_allowedip;
            while (aip) {
                wg_allowedip *next_aip = aip->next_allowedip;
                free(aip);
                aip = next_aip;
            }
            wg_peer *next_peer = peer->next_peer;
            free(peer);
            peer = next_peer;
        }
    }
    return -1;
}

/* --------------- dynamic peer management (unchanged) --------------- */

int wgctl_add_peer(const char *ifname, const uint8_t pubkey[WG_KEY_LEN], const uint8_t psk[WG_KEY_LEN], const char *allowed_ip_cidr) {
    wg_device dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, ifname, sizeof(dev.name)-1);
    dev.flags = 0;

    wg_peer peer;
    memset(&peer, 0, sizeof(peer));
    peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
    memcpy(peer.public_key, pubkey, WG_KEY_LEN);

    if (psk) {
        peer.flags |= WGPEER_HAS_PRESHARED_KEY;
        memcpy(peer.preshared_key, psk, WG_KEY_LEN);
    }

    wg_allowedip allowed;
    memset(&allowed, 0, sizeof(allowed));
    if (parse_allowed_ip(allowed_ip_cidr, &allowed) == 0) {
        peer.first_allowedip = &allowed;
        peer.last_allowedip = &allowed;
    }

    dev.first_peer = &peer;
    dev.last_peer = &peer;

    int rc = wg_set_device(&dev);
    if (rc < 0) {
        LOG_ERROR("wg_set_device add_peer failed");
        return -1;
    }
    return 0;
}

int wgctl_remove_peer(const char *ifname, const uint8_t pubkey[WG_KEY_LEN]) {
    wg_device dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.name, ifname, sizeof(dev.name)-1);
    dev.flags = 0;

    wg_peer peer;
    memset(&peer, 0, sizeof(peer));
    peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REMOVE_ME;
    memcpy(peer.public_key, pubkey, WG_KEY_LEN);

    dev.first_peer = &peer;
    dev.last_peer = &peer;

    int rc = wg_set_device(&dev);
    if (rc < 0) {
        LOG_ERROR("wg_set_device remove_peer failed");
        return -1;
    }
    return 0;
}

int wgctl_get_peer_stats(const char *ifname, const uint8_t pubkey[WG_KEY_LEN], uint64_t *rx_bytes, uint64_t *tx_bytes, int64_t *last_handshake_time) {
    wg_device *dev;
    if (wg_get_device(&dev, ifname) < 0) return -1;

    int found = -1;
    wg_peer *peer;
    wg_for_each_peer(dev, peer) {
        if (memcmp(peer->public_key, pubkey, WG_KEY_LEN) == 0) {
            if (rx_bytes) *rx_bytes = peer->rx_bytes;
            if (tx_bytes) *tx_bytes = peer->tx_bytes;
            if (last_handshake_time) *last_handshake_time = peer->last_handshake_time.tv_sec;
            found = 0;
            break;
        }
    }
    wg_free_device(dev);
    return found;
}

/* --------------- server public key --------------- */

int wgctl_get_server_pubkey(const char *ifname, uint8_t pubkey_out[WG_KEY_LEN]) {
    wg_device *dev;
    if (wg_get_device(&dev, ifname) < 0) {
        LOG_ERROR("wgctl_get_server_pubkey: wg_get_device failed for %s", ifname);
        return -1;
    }
    memcpy(pubkey_out, dev->public_key, WG_KEY_LEN);
    wg_free_device(dev);
    return 0;
}
