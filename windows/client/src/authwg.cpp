#include "authwg.h"
#include "win_http.h"
#include "cJSON.h"

#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

static std::string g_server_url;
static std::string g_session_token;
static std::atomic<bool> g_is_running(false);
static std::atomic<bool> g_is_connected(false);
static std::thread g_renew_thread;
static std::mutex g_status_mutex;
static std::string g_status = "Disconnected";

static void SetStatus(const std::string& status) {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    g_status = status;
}

static std::string GetStatus() {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    return g_status;
}

static std::string GetTempConfPath() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    return std::string(tempPath) + "wg-vpn.conf";
}

static bool InstallTunnel(const std::string& conf_path) {
    // Call wireguard.exe /installtunnelservice wg-vpn.conf
    std::string cmd = "wireguard.exe /installtunnelservice \"" + conf_path + "\"";
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // Hide the window
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000); // Wait up to 5s
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    return false;
}

static void UninstallTunnel() {
    // Call wireguard.exe /uninstalltunnelservice wg-vpn
    std::string cmd = "wireguard.exe /uninstalltunnelservice wg-vpn";
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static void RenewThreadFunc() {
    while (g_is_running) {
        // Sleep for a while (e.g., 6 hours), but we check is_running frequently
        // The server default ttl is 12h. We renew every 6 hours.
        for (int i = 0; i < 21600 && g_is_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (!g_is_running) break;

        // Make renew request
        cJSON* req = cJSON_CreateObject();
        cJSON_AddStringToObject(req, "session_token", g_session_token.c_str());
        char* req_str = cJSON_PrintUnformatted(req);
        cJSON_Delete(req);

        std::string resp;
        int status;
        if (win_http::PostJson(g_server_url + "/renew", req_str, resp, status)) {
            if (status != 200) {
                SetStatus("Renew Failed");
                // In a real app, you might want to retry or disconnect.
            }
        }
        free(req_str);
    }
}

static std::string GetAbsoluteConfPath() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = exePath;
    size_t pos = exeDir.find_last_of("\\/");
    if (pos != std::string::npos) {
        exeDir = exeDir.substr(0, pos + 1);
    }
    return exeDir + "wg-vpn.conf";
}

extern "C" {

EXPORT int CALLING_CONV WgLogin(const char* username, const char* password, const char* server_url) {
    if (g_is_running) {
        return 0; // Already running
    }

    SetStatus("Connecting...");

    cJSON* req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "username", username);
    cJSON_AddStringToObject(req, "password", password);
    char* req_str = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);

    std::string resp_str;
    int status_code = 0;
    
    g_server_url = server_url;
    // Strip trailing slash if any
    if (!g_server_url.empty() && g_server_url.back() == '/') {
        g_server_url.pop_back();
    }

    if (!win_http::PostJson(g_server_url + "/login", req_str, resp_str, status_code)) {
        free(req_str);
        SetStatus("Network Error");
        return -1;
    }
    free(req_str);

    cJSON* resp = cJSON_Parse(resp_str.c_str());
    if (!resp) {
        SetStatus("Invalid Response");
        return -2;
    }

    if (status_code != 200) {
        cJSON* err = cJSON_GetObjectItem(resp, "error");
        if (err && err->valuestring) {
            SetStatus(std::string("Auth Failed: ") + err->valuestring);
        } else {
            SetStatus("Auth Failed");
        }
        cJSON_Delete(resp);
        return -2;
    }

    // Parse config
    std::string token = cJSON_GetObjectItem(resp, "session_token")->valuestring;
    std::string priv = cJSON_GetObjectItem(resp, "client_private_key")->valuestring;
    std::string addr = cJSON_GetObjectItem(resp, "client_address")->valuestring;
    std::string srv_pub = cJSON_GetObjectItem(resp, "server_public_key")->valuestring;
    std::string psk = cJSON_GetObjectItem(resp, "preshared_key")->valuestring;
    std::string endpoint = cJSON_GetObjectItem(resp, "endpoint")->valuestring;
    std::string allowed_ips = cJSON_GetObjectItem(resp, "allowed_ips")->valuestring;
    
    cJSON* dns_item = cJSON_GetObjectItem(resp, "dns");
    std::string dns = (dns_item && dns_item->valuestring) ? dns_item->valuestring : "";

    cJSON_Delete(resp);

    g_session_token = token;

    // Generate wg-vpn.conf in the same directory as the executable using ABSOLUTE path
    std::string conf_path = GetAbsoluteConfPath();
    
    std::ofstream out(conf_path);
    if (!out) {
        SetStatus("Cannot write conf");
        return -3;
    }

    out << "[Interface]\n";
    out << "PrivateKey = " << priv << "\n";
    out << "Address = " << addr << "\n";
    if (!dns.empty()) {
        out << "DNS = " << dns << "\n";
    }
    out << "\n[Peer]\n";
    out << "PublicKey = " << srv_pub << "\n";
    out << "PresharedKey = " << psk << "\n";
    out << "Endpoint = " << endpoint << "\n";
    out << "AllowedIPs = " << allowed_ips << "\n";
    out << "PersistentKeepalive = 25\n";
    out.close();

    // Call wireguard.exe
    if (!InstallTunnel(conf_path)) {
        SetStatus("WireGuard Install Failed");
        return -4;
    }

    // Do NOT delete the conf file here! The WireGuard service needs to read it asynchronously.
    // We will delete it upon Logout.

    g_is_running = true;
    g_is_connected = true;
    SetStatus("Connected");

    // Start renew thread
    g_renew_thread = std::thread(RenewThreadFunc);

    return 0;
}

EXPORT int CALLING_CONV WgLogout(void) {
    if (!g_is_running) return 0;

    SetStatus("Disconnecting...");

    // Stop thread
    g_is_running = false;
    if (g_renew_thread.joinable()) {
        g_renew_thread.join();
    }

    // Send logout request
    cJSON* req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "session_token", g_session_token.c_str());
    char* req_str = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);

    std::string resp;
    int status;
    win_http::PostJson(g_server_url + "/logout", req_str, resp, status);
    free(req_str);

    // Uninstall tunnel
    UninstallTunnel();

    // Now it's safe to delete the conf file
    DeleteFileA(GetAbsoluteConfPath().c_str());

    g_is_connected = false;
    g_session_token.clear();
    SetStatus("Disconnected");

    return 0;
}

EXPORT int CALLING_CONV WgGetStatus(char* out_status, int max_len) {
    if (!out_status || max_len <= 0) return -1;
    std::string status = GetStatus();
    strncpy(out_status, status.c_str(), max_len - 1);
    out_status[max_len - 1] = '\0';
    return 0;
}

} // extern "C"
