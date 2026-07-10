#include "win_http.h"
#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace {
    std::wstring Utf8ToWide(const std::string& str) {
        if (str.empty()) return L"";
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstrTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
        return wstrTo;
    }
}

namespace win_http {

bool PostJson(const std::string& url_in, const std::string& json_body, std::string& response_body, int& status_code, bool insecure) {
    status_code = 0;
    response_body.clear();

    std::wstring w_url = Utf8ToWide(url_in);
    
    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    
    wchar_t hostName[256];
    wchar_t urlPath[1024];
    
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName) / sizeof(hostName[0]);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(urlPath[0]);
    
    if (!WinHttpCrackUrl(w_url.c_str(), 0, 0, &urlComp)) {
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"AuthWg-Windows-Client/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    // Default to HTTPS if port 443 or scheme is HTTPS.
    // In auth-wg, the server may use a custom port (e.g., 8443) with TLS.
    // We detect if it starts with https://
    bool is_https = (url_in.find("https://") == 0);

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD dwOpenRequestFlag = is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            dwOpenRequestFlag);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (insecure) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    LPCWSTR header = L"Content-Type: application/json\r\n";
    BOOL bResults = WinHttpSendRequest(hRequest,
                                       header, -1L,
                                       (LPVOID)json_body.c_str(), (DWORD)json_body.size(),
                                       (DWORD)json_body.size(), 0);

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (bResults) {
        DWORD dwSize = sizeof(DWORD);
        DWORD dwStatusCode = 0;
        WinHttpQueryHeaders(hRequest, 
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, 
                            &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
        status_code = dwStatusCode;

        DWORD dwSizeAvail = 0;
        DWORD dwDownloaded = 0;
        do {
            dwSizeAvail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSizeAvail)) {
                break;
            }
            if (dwSizeAvail == 0) {
                break;
            }

            std::vector<char> buffer(dwSizeAvail + 1, 0);
            if (WinHttpReadData(hRequest, (LPVOID)buffer.data(), dwSizeAvail, &dwDownloaded)) {
                response_body.append(buffer.data(), dwDownloaded);
            }
        } while (dwSizeAvail > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bResults == TRUE;
}

} // namespace win_http
