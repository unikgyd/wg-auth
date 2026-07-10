#ifndef AUTHWG_H
#define AUTHWG_H

#ifdef _WIN32
  #define EXPORT __declspec(dllexport)
  #define CALLING_CONV __stdcall
#else
  #define EXPORT
  #define CALLING_CONV
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Login to the VPN server and establish the WireGuard tunnel.
 * 
 * @param username The account username.
 * @param password The account password.
 * @param server_url The full HTTPS API URL (e.g. "https://198.51.100.1:8443").
 * @return int 0 on success, <0 on error (e.g. -1 for network error, -2 for auth failed).
 */
EXPORT int CALLING_CONV WgLogin(const char* username, const char* password, const char* server_url);

/**
 * @brief Logout from the VPN server and teardown the WireGuard tunnel.
 * 
 * @return int 0 on success, <0 on error.
 */
EXPORT int CALLING_CONV WgLogout(void);

/**
 * @brief Get the current status of the VPN connection.
 * 
 * @param out_status A buffer to receive the status string (e.g. "Connected", "Disconnected").
 * @param max_len The size of the out_status buffer.
 * @return int 0 on success, <0 on error.
 */
EXPORT int CALLING_CONV WgGetStatus(char* out_status, int max_len);

/**
 * @brief Set insecure mode (skip TLS certificate validation).
 * 
 * @param insecure Non-zero to enable insecure mode, 0 for secure (default).
 */
EXPORT void CALLING_CONV WgSetInsecure(int insecure);

#ifdef __cplusplus
}
#endif

#endif // AUTHWG_H
