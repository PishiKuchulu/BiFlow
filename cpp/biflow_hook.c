#define WIN32_LEAN_AND_MEAN
#include "minhook/include/MinHook.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// BiFlow Winsock hook DLL.
//
// Strategy: outbound client sockets are bound to the IPv4 address of the
// physical ("direct") adapter BiFlow selected. On Windows, binding a socket to
// a specific local address pins its egress to the owning interface, so the
// traffic leaves via the physical adapter instead of the VPN tunnel.
//
// Policy distribution (written by BiFlow, read here):
//   1. %TEMP%\biflow_target_ip.txt            -> target IPv4 (one line)
//   2. %ProgramData%\BiFlow\target_ip.txt    -> same, cross-user fallback
//   3. %TEMP%\BiFlow\bypass_apps.txt          -> allowed exe paths (one per line)
//   4. %ProgramData%\BiFlow\bypass_apps.txt   -> same, cross-user fallback
//   5. BIFLOW_TARGET_IP env var               -> bootstrap only, read once at attach
//
// The hook re-validates the policy on every intercepted call by fingerprinting
// the policy files (last-write time). Deleting the files (BiFlow "Disable All"
// / "Exit") therefore disables the bypass for NEW sockets in already-injected
// processes; removing one app from the allow-list stops its bypass while other
// apps keep theirs. Already-established connections are never migrated.

typedef int(WSAAPI *pfn_connect)(SOCKET s, const struct sockaddr *name,
                                 int namelen);
typedef int(WSAAPI *pfn_WSAConnect)(SOCKET s, const struct sockaddr *name,
                                    int namelen, LPWSABUF lpCallerData,
                                    LPWSABUF lpCalleeData, LPQOS lpSQOS,
                                    LPQOS lpGQOS);
typedef int(WSAAPI *pfn_sendto)(SOCKET s, const char *buf, int len, int flags,
                                const struct sockaddr *to, int tolen);
typedef int(WSAAPI *pfn_WSASendTo)(SOCKET s, LPWSABUF lpBuffers,
                                   DWORD dwBufferCount,
                                   LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                                   const struct sockaddr *lpTo, int iToLen,
                                   LPWSAOVERLAPPED lpOverlapped,
                                   LPWSAOVERLAPPED_COMPLETION_ROUTINE
                                       lpCompletionRoutine);
typedef int(WSAAPI *pfn_bind)(SOCKET s, const struct sockaddr *name,
                              int namelen);

static pfn_connect g_real_connect = NULL;
static pfn_WSAConnect g_real_WSAConnect = NULL;
static pfn_sendto g_real_sendto = NULL;
static pfn_WSASendTo g_real_WSASendTo = NULL;
static pfn_bind g_real_bind = NULL;

// Cached policy. g_target_ip == 0 means "bypass disabled, do not bind".
static uint32_t g_target_ip = 0;   // Network byte order
static uint64_t g_policy_tick = 0; // Fingerprint of the policy files
static int g_this_exe_allowed = 1; // 0 when this exe was removed from bypass

static uint32_t parse_ip_string(char *buf) {
  if (!buf)
    return 0;

  // Trim leading whitespace
  while (*buf == ' ' || *buf == '\t')
    buf++;

  // Terminate at pipe, carriage return, newline, or space
  char *p = buf;
  while (*p) {
    if (*p == '|' || *p == '\r' || *p == '\n' || *p == ' ' || *p == '\t') {
      *p = '\0';
      break;
    }
    p++;
  }

  if (*buf == '\0')
    return 0;

  unsigned long ip = inet_addr(buf);
  if (ip != INADDR_NONE && ip != 0) {
    return (uint32_t)ip;
  }
  return 0;
}

// kind: 0 = %TEMP%\biflow_target_ip.txt
//       1 = %ProgramData%\BiFlow\target_ip.txt
//       2 = %TEMP%\BiFlow\bypass_apps.txt
//       3 = %ProgramData%\BiFlow\bypass_apps.txt
static int policy_file_path(char *out, size_t out_size, int kind) {
  if (kind == 0) {
    char tmp[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmp) == 0)
      return -1;
    if (strcat_s(tmp, MAX_PATH, "biflow_target_ip.txt") != 0)
      return -1;
    if (strcpy_s(out, out_size, tmp) != 0)
      return -1;
    return 0;
  }
  if (kind == 1 || kind == 3) {
    char prog[MAX_PATH];
    if (GetEnvironmentVariableA("ProgramData", prog, sizeof(prog)) == 0)
      return -1;
    const char *leaf =
        (kind == 1) ? "target_ip.txt" : "bypass_apps.txt";
    if (sprintf_s(out, out_size, "%s\\BiFlow\\%s", prog, leaf) < 0)
      return -1;
    return 0;
  }
  // kind == 2
  {
    char tmp[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmp) == 0)
      return -1;
    if (strcat_s(tmp, MAX_PATH, "BiFlow\\bypass_apps.txt") != 0)
      return -1;
    if (strcpy_s(out, out_size, tmp) != 0)
      return -1;
    return 0;
  }
}

// Fingerprint of all policy files (last-write times). 0 when none exist.
// Cheap: one GetFileAttributesExA per policy file.
static uint64_t policy_files_tick(void) {
  uint64_t tick = 0;
  for (int i = 0; i < 4; i++) {
    char path[MAX_PATH];
    if (policy_file_path(path, sizeof(path), i) != 0)
      continue;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
      uint64_t t = ((uint64_t)fad.ftLastWriteTime.dwHighDateTime << 32) |
                   (uint64_t)fad.ftLastWriteTime.dwLowDateTime;
      tick ^= t + 0x9e3779b97f4a7c15ULL + (tick << 6) + (tick >> 2);
    }
  }
  return tick;
}

static uint32_t load_target_ip_from_files(void) {
  char buf[128];
  for (int i = 0; i < 2; i++) {
    char path[MAX_PATH];
    if (policy_file_path(path, sizeof(path), i) != 0)
      continue;
    FILE *f = NULL;
    if (fopen_s(&f, path, "r") == 0 && f) {
      buf[0] = '\0';
      if (fgets(buf, sizeof(buf), f)) {
        fclose(f);
        uint32_t ip = parse_ip_string(buf);
        if (ip != 0)
          return ip;
      } else {
        fclose(f);
      }
    }
  }
  return 0;
}

// Returns 1 when this process's executable is listed in bypass_apps.txt.
// Missing list file => permissive (1), for forward compatibility.
static int load_this_exe_allowed(void) {
  char self[MAX_PATH];
  DWORD n = GetModuleFileNameA(NULL, self, MAX_PATH);
  if (n == 0 || n >= MAX_PATH)
    return 1;

  char buf[1024];
  int found_list = 0;
  for (int i = 2; i < 4; i++) {
    char path[MAX_PATH];
    if (policy_file_path(path, sizeof(path), i) != 0)
      continue;
    FILE *f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f)
      continue;
    found_list = 1;
    while (fgets(buf, sizeof(buf), f)) {
      // Trim trailing CR/LF/whitespace
      size_t len = strlen(buf);
      while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' ||
                         buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
        buf[--len] = '\0';
      }
      if (len > 0 && _stricmp(buf, self) == 0) {
        fclose(f);
        return 1;
      }
    }
    fclose(f);
  }
  // If a list exists and we are not on it, this app's bypass was removed.
  return found_list ? 0 : 1;
}

// Full policy load used once at DLL attach: files first, then the
// BIFLOW_TARGET_IP environment variable as a bootstrap fallback.
static uint32_t load_target_ip_initial(void) {
  uint32_t ip = load_target_ip_from_files();
  if (ip != 0)
    return ip;
  char buf[128] = {0};
  if (GetEnvironmentVariableA("BIFLOW_TARGET_IP", buf, sizeof(buf)) > 0)
    return parse_ip_string(buf);
  return 0;
}

// Re-read policy when BiFlow changed or deleted the policy files.
// After this, g_target_ip == 0 means disabled (files deleted) and
// g_this_exe_allowed == 0 means this app was removed from bypass.
static void refresh_policy(void) {
  uint64_t tick = policy_files_tick();
  if (tick != g_policy_tick) {
    g_policy_tick = tick;
    g_target_ip = load_target_ip_from_files();
    g_this_exe_allowed = load_this_exe_allowed();
  }
}

static int policy_active(void) {
  return g_target_ip != 0 && g_this_exe_allowed;
}

static void bind_socket_if_needed(SOCKET s) {
  refresh_policy();
  if (!policy_active())
    return;

  struct sockaddr_in current;
  int len = sizeof(current);
  if (getsockname(s, (struct sockaddr *)&current, &len) == 0) {
    if (current.sin_family == AF_INET &&
        current.sin_addr.s_addr == INADDR_ANY) {
      struct sockaddr_in bind_addr;
      memset(&bind_addr, 0, sizeof(bind_addr));
      bind_addr.sin_family = AF_INET;
      bind_addr.sin_addr.s_addr = g_target_ip;
      bind_addr.sin_port = 0;
      if (g_real_bind) {
        g_real_bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
      } else {
        bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
      }
    }
  }
}

static int WSAAPI Hook_bind(SOCKET s, const struct sockaddr *name,
                            int namelen) {
  refresh_policy();
  if (policy_active() && name &&
      namelen >= (int)sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)name;
    // Only redirect outbound client sockets that bind to INADDR_ANY on port 0
    // (used by asynchronous APIs such as ConnectEx).
    if (in->sin_family == AF_INET && in->sin_addr.s_addr == INADDR_ANY &&
        in->sin_port == 0) {
      struct sockaddr_in redirected;
      memcpy(&redirected, in, sizeof(redirected));
      redirected.sin_addr.s_addr = g_target_ip;
      if (g_real_bind) {
        return g_real_bind(s, (struct sockaddr *)&redirected,
                           sizeof(redirected));
      }
    }
  }
  if (g_real_bind) {
    return g_real_bind(s, name, namelen);
  }
  return bind(s, name, namelen);
}

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name,
                               int namelen) {
  if (name && name->sa_family == AF_INET) {
    bind_socket_if_needed(s);
  }
  if (g_real_connect) {
    return g_real_connect(s, name, namelen);
  }
  return connect(s, name, namelen);
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name,
                                  int namelen, LPWSABUF lpCallerData,
                                  LPWSABUF lpCalleeData, LPQOS lpSQOS,
                                  LPQOS lpGQOS) {
  if (name && name->sa_family == AF_INET) {
    bind_socket_if_needed(s);
  }
  if (g_real_WSAConnect) {
    return g_real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData,
                             lpSQOS, lpGQOS);
  }
  return WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS,
                    lpGQOS);
}

static int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
                              const struct sockaddr *to, int tolen) {
  if (to && to->sa_family == AF_INET) {
    bind_socket_if_needed(s);
  }
  if (g_real_sendto) {
    return g_real_sendto(s, buf, len, flags, to, tolen);
  }
  return sendto(s, buf, len, flags, to, tolen);
}

static int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF lpBuffers,
                                 DWORD dwBufferCount,
                                 LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                                 const struct sockaddr *lpTo, int iToLen,
                                 LPWSAOVERLAPPED lpOverlapped,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE
                                     lpCompletionRoutine) {
  if (lpTo && lpTo->sa_family == AF_INET) {
    bind_socket_if_needed(s);
  }
  if (g_real_WSASendTo) {
    return g_real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                            dwFlags, lpTo, iToLen, lpOverlapped,
                            lpCompletionRoutine);
  }
  return WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
                   lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

static void init_hooks(void) {
  g_target_ip = load_target_ip_initial();
  g_policy_tick = policy_files_tick();
  g_this_exe_allowed = load_this_exe_allowed();

  if (MH_Initialize() != MH_OK) {
    return;
  }

  MH_CreateHookApi(L"ws2_32.dll", "bind", (LPVOID)&Hook_bind,
                   (LPVOID *)&g_real_bind);
  MH_CreateHookApi(L"ws2_32.dll", "connect", (LPVOID)&Hook_connect,
                   (LPVOID *)&g_real_connect);
  MH_CreateHookApi(L"ws2_32.dll", "WSAConnect", (LPVOID)&Hook_WSAConnect,
                   (LPVOID *)&g_real_WSAConnect);
  MH_CreateHookApi(L"ws2_32.dll", "sendto", (LPVOID)&Hook_sendto,
                   (LPVOID *)&g_real_sendto);
  MH_CreateHookApi(L"ws2_32.dll", "WSASendTo", (LPVOID)&Hook_WSASendTo,
                   (LPVOID *)&g_real_WSASendTo);
  MH_EnableHook(MH_ALL_HOOKS);
}

static void cleanup_hooks(void) {
  MH_DisableHook(MH_ALL_HOOKS);
  MH_Uninitialize();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  (void)lpReserved;
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(hinstDLL);
    init_hooks();
    break;
  case DLL_PROCESS_DETACH:
    cleanup_hooks();
    break;
  }
  return TRUE;
}
