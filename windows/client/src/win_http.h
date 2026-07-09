#ifndef WIN_HTTP_H
#define WIN_HTTP_H

#include <string>

namespace win_http {
    /**
     * @brief Sends an HTTPS POST request with JSON payload using Windows WinHTTP.
     * 
     * @param url The full URL (e.g. "https://198.51.100.1:8443/login")
     * @param json_body The JSON payload string.
     * @param response_body Out parameter for the response body.
     * @param status_code Out parameter for the HTTP status code.
     * @return true on network success (even if status_code is 4xx/5xx).
     * @return false on network error.
     */
    bool PostJson(const std::string& url, const std::string& json_body, std::string& response_body, int& status_code);
}

#endif // WIN_HTTP_H
