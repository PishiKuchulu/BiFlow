#define WIN32_LEAN_AND_MEAN
#include "minhook/include/MinHook.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// BiFlow Winsock hook DLL (v0.3.0).
//
// Strategy: outbound client sockets are bound to the IPv4 address of the
// physical ("direct") adapter BiFlow selected. On Windows, binding a socket to
// a specific local address pins its egress to the owning interface, so the
// traffic leaves via the physical adapter instead of the VPN tunnel.
//
// Policy distribution (written by the elevated BiFlow process, read here):
//   1. %ProgramData%\BiFlow\target_ip.txt    -> target IPv4 (one line)
//   2. %ProgramData%\BiFlow\bypass_apps.txt  -> allowed exe paths (UTF-8, one per line)
//   3. %TEMP%\biflow_target_ip.txt           -> legacy fallback, only when (1) is absent
//   4. %TEMP%\BiFlow\bypass_apps.txt         -> legacy fallback, only when (2) is absent
//
// The ProgramData copies live in a directory whose DACL (set by BiFlow) grants
// write access only to SYSTEM and Administrators, and they are authoritative:
// the %TEMP% fallbacks can no longer override them. BIFLOW_TARGET_IP is NOT
// consulted anymore (it leaked into unrelated child processes of BiFlow).
//
// The hook re-validates the policy at most every 250 ms by fingerprinting the
// policy files (last-write times). Deleting the files (BiFlow "Disable All" /
// "Exit") therefore disables the bypass for NEW sockets in already-injected
// processes; removing one app from the allow-list stops its bypass while other
// apps keep theirs. Already-established connections are never migrated.
//
// After installing its hooks the DLL writes a status file
// (hook_status_<pid>.txt next to the policy files) so BiFlow can distinguish
// "DLL loaded" from "hooks actually active".
//
// All file/path handling uses the wide (W) APIs and the allow-list is decoded
// as UTF-8, so user names and install paths containing non-ASCII characters
// (e.g. Persian) work correctly.

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

// Policy file paths, built once by the init thread before hooks are enabled.
static wchar_t g_path_target_pd[1024];
static wchar_t g_path_apps_pd[1024];
static wchar_t g_path_target_tmp[1024];
static wchar_t g_path_apps_tmp[1024];
static wchar_t g_path_status[1024];

// Cached policy, guarded by g_policy_lock. g_target_ip == 0 means "bypass
// disabled, do not bind". Readers take a consistent snapshot under the lock
// instead of racing with a refresh on another thread.
static SRWLOCK g_policy_lock = SRWLOCK_INIT;
static uint32_t g_target_ip = 0;   // Network byte order
static uint64_t g_policy_tick = 0; // Fingerprint of the policy files
static int g_this_exe_allowed = 1; // 0 when this exe was removed from bypass
static ULONGLONG g_last_check_ms = 0;

static volatile LONG g_hooks_ready = 0;
static int g_hooks_installed = 0;

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

static void build_policy_paths(void) {
  wchar_t tmp[1024];
  wchar_t prog[1024];
  DWORD pid = GetCurrentProcessId();

  g_path_target_pd[0] = L'\0';
  g_path_apps_pd[0] = L'\0';
  g_path_target_tmp[0] = L'\0';
  g_path_apps_tmp[0] = L'\0';
  g_path_status[0] = L'\0';

  if (GetEnvironmentVariableW(L"ProgramData", prog, 1024) > 0) {
    _snwprintf_s(g_path_target_pd, 1024, _TRUNCATE, L"%s\\BiFlow\\target_ip.txt",
                 prog);
    _snwprintf_s(g_path_apps_pd, 1024, _TRUNCATE, L"%s\\BiFlow\\bypass_apps.txt",
                 prog);
    _snwprintf_s(g_path_status, 1024, _TRUNCATE,
                 L"%s\\BiFlow\\hook_status_%lu.txt", prog, (unsigned long)pid);
  }
  if (GetTempPathW(1024, tmp) > 0) {
    _snwprintf_s(g_path_target_tmp, 1024, _TRUNCATE, L"%sbiflow_target_ip.txt",
                 tmp);
    _snwprintf_s(g_path_apps_tmp, 1024, _TRUNCATE,
                 L"%sBiFlow\\bypass_apps.txt", tmp);
    if (g_path_status[0] == L'\0') {
      _snwprintf_s(g_path_status, 1024, _TRUNCATE,
                   L"%sBiFlow\\hook_status_%lu.txt", tmp, (unsigned long)pid);
    }
  }
}

// Fingerprint of all policy files (last-write times). 0 when none exist.
// Cheap: one GetFileAttributesExW per policy file.
static uint64_t policy_files_tick(void) {
  const wchar_t *paths[4] = {g_path_target_pd, g_path_apps_pd,
                             g_path_target_tmp, g_path_apps_tmp};
  uint64_t tick = 0;
  for (int i = 0; i < 4; i++) {
    if (paths[i][0] == L'\0')
      continue;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(paths[i], GetFileExInfoStandard, &fad)) {
      uint64_t t = ((uint64_t)fad.ftLastWriteTime.dwHighDateTime << 32) |
                   (uint64_t)fad.ftLastWriteTime.dwLowDateTime;
      tick ^= t + 0x9e3779b97f4a7c15ULL + (tick << 6) + (tick >> 2);
    }
  }
  return tick;
}

// Read a whole small file as bytes. Returns byte count, or -1 when the file
// does not exist / cannot be opened.
static int read_small_file(const wchar_t *path, char *buf, int buf_size) {
  FILE *f = NULL;
  if (_wfopen_s(&f, path, L"rb") != 0 || !f)
    return -1;
  size_t n = fread(buf, 1, (size_t)buf_size - 1, f);
  fclose(f);
  buf[n] = '\0';
  return (int)n;
}

static uint32_t load_target_ip_from_files(void) {
  char buf[256];
  // ProgramData (admin-only) first, TEMP only as a legacy fallback.
  const wchar_t *paths[2] = {g_path_target_pd, g_path_target_tmp};
  for (int i = 0; i < 2; i++) {
    if (paths[i][0] == L'\0')
      continue;
    if (read_small_file(paths[i], buf, sizeof(buf)) > 0) {
      uint32_t ip = parse_ip_string(buf);
      if (ip != 0)
        return ip;
    }
  }
  return 0;
}

// Returns 1 when this process's executable is listed in bypass_apps.txt.
// Missing list file => permissive (1), for forward compatibility.
// The list is UTF-8 text written by BiFlow; it is decoded to wide chars and
// compared against the wide module path, so non-ASCII paths match correctly.
static int load_this_exe_allowed(void) {
  wchar_t self[1024];
  DWORD n = GetModuleFileNameW(NULL, self, 1024);
  if (n == 0 || n >= 1024)
    return 1;

  static char raw[64 * 1024];
  static wchar_t wide[64 * 1024];
  const wchar_t *paths[2] = {g_path_apps_pd, g_path_apps_tmp};
  for (int i = 0; i < 2; i++) {
    if (paths[i][0] == L'\0')
      continue;
    int len = read_small_file(paths[i], raw, sizeof(raw));
    if (len < 0)
      continue; // No list at this location; try the fallback.
    // A list file exists here and is authoritative for this check.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, raw, len, wide,
                                   (int)(sizeof(wide) / sizeof(wide[0])) - 1);
    if (wlen <= 0)
      return 0;
    wide[wlen] = L'\0';
    wchar_t *line = wide;
    while (line && *line) {
      wchar_t *eol = wcschr(line, L'\n');
      if (eol)
        *eol = L'\0';
      // Trim trailing CR / spaces / tabs
      size_t llen = wcslen(line);
      while (llen > 0 && (line[llen - 1] == L'\r' || line[llen - 1] == L' ' ||
                         line[llen - 1] == L'\t')) {
        line[--llen] = L'\0';
      }
      // Trim leading spaces / tabs
      while (*line == L' ' || *line == L'\t')
        line++;
      if (llen > 0 && _wcsicmp(line, self) == 0) {
        return 1;
      }
      line = eol ? eol + 1 : NULL;
    }
    // List exists and we are not on it: this app's bypass was removed.
    return 0;
  }
  // No list anywhere: permissive.
  return 1;
}

// Re-read policy when BiFlow changed or deleted the policy files.
// Called with g_policy_lock held exclusively.
static void refresh_policy_locked(void) {
  uint64_t tick = policy_files_tick();
  if (tick != g_policy_tick) {
    g_policy_tick = tick;
    g_target_ip = load_target_ip_from_files();
    g_this_exe_allowed = load_this_exe_allowed();
  }
  g_last_check_ms = GetTickCount64();
}

// Take a consistent snapshot of the current policy. Re-checks the policy
// files at most once per 250 ms so the per-packet cost stays low.
static void policy_snapshot(uint32_t *out_ip, int *out_allowed) {
  AcquireSRWLockShared(&g_policy_lock);
  ULONGLONG now = GetTickCount64();
  int stale = (now - g_last_check_ms) >= 250;
  if (stale) {
    // Upgrade to exclusive for the refresh.
    ReleaseSRWLockShared(&g_policy_lock);
    AcquireSRWLockExclusive(&g_policy_lock);
    refresh_policy_locked();
    *out_ip = g_target_ip;
    *out_allowed = g_this_exe_allowed;
    ReleaseSRWLockExclusive(&g_policy_lock);
    return;
  }
  *out_ip = g_target_ip;
  *out_allowed = g_this_exe_allowed;
  ReleaseSRWLockShared(&g_policy_lock);
}

static int policy_active_snapshot(uint32_t *out_ip) {
  int allowed = 0;
  policy_snapshot(out_ip, &allowed);
  return *out_ip != 0 && allowed;
}

// Destinations that must never be re-bound to the physical adapter: loopback,
// link-local, multicast, broadcast and unspecified traffic stays on its
// original route (binding it to the physical source address breaks it).
static int dest_is_special(const struct sockaddr_in *in) {
  uint32_t ip = ntohl(in->sin_addr.s_addr);
  if (ip == 0 || ip == 0xFFFFFFFFu)
    return 1; // unspecified / limited broadcast
  if ((ip >> 24) == 127)
    return 1; // loopback 127.0.0.0/8
  if ((ip >> 16) == 0xA9FE)
    return 1; // link-local 169.254.0.0/16
  if ((ip >> 28) == 0xE)
    return 1; // multicast 224.0.0.0/4
  return 0;
}

// Bind an unbound socket to the target address. If the socket was already
// bound (to anything) the bind simply fails and the result is ignored, so
// deliberately pre-bound sockets are never disturbed.
static void bind_socket_if_needed(SOCKET s, const struct sockaddr_in *dest) {
  uint32_t target_ip = 0;
  if (!policy_active_snapshot(&target_ip))
    return;
  if (dest && dest_is_special(dest))
    return;

  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = target_ip;
  bind_addr.sin_port = 0;
  if (g_real_bind) {
    g_real_bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
  } else {
    bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
  }
}

static int WSAAPI Hook_bind(SOCKET s, const struct sockaddr *name,
                            int namelen) {
  uint32_t target_ip = 0;
  if (policy_active_snapshot(&target_ip) && name &&
      namelen >= (int)sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)name;
    // Only redirect outbound client sockets that bind to INADDR_ANY on port 0
    // (used by asynchronous APIs such as ConnectEx). UDP sockets are left
    // alone here (their bypass happens in sendto/WSASendTo) so UDP listeners
    // and discovery sockets keep working on all interfaces.
    if (in->sin_family == AF_INET && in->sin_addr.s_addr == INADDR_ANY &&
        in->sin_port == 0) {
      int sock_type = 0;
      int opt_len = sizeof(sock_type);
      if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&sock_type, &opt_len) ==
              0 &&
          sock_type == SOCK_STREAM) {
        struct sockaddr_in redirected;
        memcpy(&redirected, in, sizeof(redirected));
        redirected.sin_addr.s_addr = target_ip;
        if (g_real_bind) {
          int rc = g_real_bind(s, (struct sockaddr *)&redirected,
                               sizeof(redirected));
          if (rc != SOCKET_ERROR) {
            return rc;
          }
          // The stored target IP may be stale (DHCP renewal, adapter
          // unplugged). Never break the app: fall back to its original bind.
          return g_real_bind(s, name, namelen);
        }
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
    bind_socket_if_needed(s, (const struct sockaddr_in *)name);
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
    bind_socket_if_needed(s, (const struct sockaddr_in *)name);
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
    bind_socket_if_needed(s, (const struct sockaddr_in *)to);
  } else if (!to) {
    bind_socket_if_needed(s, NULL);
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
    bind_socket_if_needed(s, (const struct sockaddr_in *)lpTo);
  } else if (!lpTo) {
    bind_socket_if_needed(s, NULL);
  }
  if (g_real_WSASendTo) {
    return g_real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                            dwFlags, lpTo, iToLen, lpOverlapped,
                            lpCompletionRoutine);
  }
  return WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
                   lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

// Report hook installation status so BiFlow's UI can be honest about whether
// the bypass is really live. Content: "OK <n>" or "ERR <stage>".
static void write_status_file(const char *status) {
  if (g_path_status[0] == L'\0')
    return;
  HANDLE h = CreateFileW(g_path_status, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return;
  DWORD written = 0;
  WriteFile(h, status, (DWORD)strlen(status), &written, NULL);
  CloseHandle(h);
}

static DWORD WINAPI init_thread(LPVOID param) {
  (void)param;
  build_policy_paths();

  AcquireSRWLockExclusive(&g_policy_lock);
  g_policy_tick = policy_files_tick();
  g_target_ip = load_target_ip_from_files();
  g_this_exe_allowed = load_this_exe_allowed();
  g_last_check_ms = GetTickCount64();
  ReleaseSRWLockExclusive(&g_policy_lock);

  if (MH_Initialize() != MH_OK) {
    write_status_file("ERR mh_initialize");
    return 0;
  }

  int installed = 0;
  if (MH_CreateHookApi(L"ws2_32.dll", "bind", (LPVOID)&Hook_bind,
                       (LPVOID *)&g_real_bind) == MH_OK)
    installed++;
  if (MH_CreateHookApi(L"ws2_32.dll", "connect", (LPVOID)&Hook_connect,
                       (LPVOID *)&g_real_connect) == MH_OK)
    installed++;
  if (MH_CreateHookApi(L"ws2_32.dll", "WSAConnect", (LPVOID)&Hook_WSAConnect,
                       (LPVOID *)&g_real_WSAConnect) == MH_OK)
    installed++;
  if (MH_CreateHookApi(L"ws2_32.dll", "sendto", (LPVOID)&Hook_sendto,
                       (LPVOID *)&g_real_sendto) == MH_OK)
    installed++;
  if (MH_CreateHookApi(L"ws2_32.dll", "WSASendTo", (LPVOID)&Hook_WSASendTo,
                       (LPVOID *)&g_real_WSASendTo) == MH_OK)
    installed++;

  if (installed == 0 || MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "ERR enable_hooks %d", installed);
    write_status_file(buf);
    return 0;
  }

  g_hooks_installed = installed;
  InterlockedExchange(&g_hooks_ready, 1);
  {
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "OK %d", installed);
    write_status_file(buf);
  }
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(hinstDLL);
    // Do the heavy work (file IO, MinHook setup which suspends threads) on a
    // fresh thread, NOT under the loader lock held during DllMain.
    {
      HANDLE th = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
      if (th)
        CloseHandle(th);
    }
    break;
  case DLL_PROCESS_DETACH:
    // When the process is terminating (lpReserved != NULL) the loader is
    // already tearing down; touching MinHook then is unsafe, so do nothing.
    if (lpReserved == NULL && InterlockedExchange(&g_hooks_ready, 0)) {
      MH_DisableHook(MH_ALL_HOOKS);
      MH_Uninitialize();
    }
    break;
  }
  return TRUE;
}
