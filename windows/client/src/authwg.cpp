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

static std::string GetAbsoluteConfPath();

static const char* SafeGetString(cJSON* obj, const char* key) {
    cJSON* item = cJSON_GetObjectItem(obj, key);
    if (item && cJSON_IsString(item) && item->valuestring) {
        return item->valuestring;
    }
    return NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_DETACH) {
        // Best-effort cleanup of sensitive conf file on exit
        DeleteFileA(GetAbsoluteConfPath().c_str());
    }
    return TRUE;
}

static std::string g_server_url;
static std::string g_session_token;
static std::atomic<bool> g_insecure(false);
static std::atomic<bool> g_is_running(false);
static std::atomic<bool> g_is_connected(false);
static std::thread g_renew_thread;
static std::mutex g_status_mutex;
static std::string g_status = "Disconnected";

static void SecureClearString(std::string& s) {
    if (!s.empty()) {
        SecureZeroMemory(&s[0], s.size());
    }
    s.clear();
}

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
    // Use absolute path for wireguard.exe to prevent PATH hijacking
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = exePath;
    size_t pos = exeDir.find_last_of("\\/");
    if (pos != std::string::npos) exeDir = exeDir.substr(0, pos + 1);
    std::string wgPath = exeDir + "wireguard.exe";
    std::string wgExe = "\"" + wgPath + "\"";
    std::string cmd = wgExe + " /installtunnelservice \"" + conf_path + "\"";
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // Hide the window
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(wgPath.c_str(), (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD exitCode = 0;
        if (WaitForSingleObject(pi.hProcess, 5000) == WAIT_TIMEOUT) {
            // Attempt to terminate if it hangs
            TerminateProcess(pi.hProcess, 1);
            exitCode = 1;
        } else {
            GetExitCodeProcess(pi.hProcess, &exitCode);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    return false;
}

static void UninstallTunnel() {
    // Use absolute path for wireguard.exe to prevent PATH hijacking
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = exePath;
    size_t pos = exeDir.find_last_of("\\/");
    if (pos != std::string::npos) exeDir = exeDir.substr(0, pos + 1);
    std::string wgPath = exeDir + "wireguard.exe";
    std::string wgExe = "\"" + wgPath + "\"";
    std::string cmd = wgExe + " /uninstalltunnelservice wg-vpn";
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(wgPath.c_str(), (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD exitCode = 0;
        if (WaitForSingleObject(pi.hProcess, 5000) == WAIT_TIMEOUT) {
            // Attempt to terminate if it hangs
            TerminateProcess(pi.hProcess, 1);
            exitCode = 1;
        } else {
            GetExitCodeProcess(pi.hProcess, &exitCode);
        }
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
        if (win_http::PostJson(g_server_url + "/renew", req_str, resp, status, g_insecure.load())) {
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

    std::string s_server_url = server_url ? server_url : "";
    if (s_server_url.empty() || (s_server_url.find("https://") != 0 && s_server_url.find("http://") != 0)) {
        SetStatus("Server URL must start with https:// or http://");
        return -1;
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

    if (!win_http::PostJson(g_server_url + "/login", req_str, resp_str, status_code, g_insecure.load())) {
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

    // Parse config (null-safe)
    const char* s_token = SafeGetString(resp, "session_token");
    const char* s_priv = SafeGetString(resp, "client_private_key");
    const char* s_client_addr = SafeGetString(resp, "client_address");
    const char* s_srv_pub = SafeGetString(resp, "server_public_key");
    const char* s_psk = SafeGetString(resp, "preshared_key");
    const char* s_endpoint = SafeGetString(resp, "endpoint");
    const char* s_allowed = SafeGetString(resp, "allowed_ips");

    if (!s_token || !s_priv || !s_client_addr || !s_srv_pub || !s_psk || !s_endpoint || !s_allowed) {
        cJSON_Delete(resp);
        SetStatus("Invalid server response (missing fields)");
        return -2;
    }

    std::string token = s_token;
    std::string priv = s_priv;
    std::string addr = s_client_addr;
    std::string srv_pub = s_srv_pub;
    std::string psk = s_psk;
    std::string endpoint = s_endpoint;
    std::string allowed_ips = s_allowed;

    cJSON* dns_item = cJSON_GetObjectItem(resp, "dns");
    std::string dns = (dns_item && cJSON_IsString(dns_item) && dns_item->valuestring) ? dns_item->valuestring : "";

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

    // Securely zero sensitive key material
    SecureClearString(priv);
    SecureClearString(psk);
    SecureClearString(resp_str);

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
    win_http::PostJson(g_server_url + "/logout", req_str, resp, status, g_insecure.load());
    free(req_str);

    // Uninstall tunnel
    UninstallTunnel();

    // Now it's safe to delete the conf file
    DeleteFileA(GetAbsoluteConfPath().c_str());

    g_is_connected = false;
    SecureClearString(g_session_token);
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

EXPORT void CALLING_CONV WgSetInsecure(int insecure) {
    g_insecure = (insecure != 0);
}

} // extern "C"
