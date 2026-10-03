#define WIN32_LEAN_AND_MEAN
#include "minhook/include/MinHook.h"
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

typedef int(WSAAPI *pfn_connect)(SOCKET s, const struct sockaddr *name,
                                 int namelen);
typedef int(WSAAPI *pfn_WSAConnect)(SOCKET s, const struct sockaddr *name,
                                    int namelen, LPWSABUF lpCallerData,
                                    LPWSABUF lpCalleeData, LPQOS lpSQOS,
                                    LPQOS lpGQOS);
typedef int(WSAAPI *pfn_sendto)(SOCKET s, const char *buf, int len, int flags,
                                const struct sockaddr *to, int tolen);
typedef int(WSAAPI *pfn_bind)(SOCKET s, const struct sockaddr *name,
                              int namelen);

static pfn_connect g_real_connect = NULL;
static pfn_WSAConnect g_real_WSAConnect = NULL;
static pfn_sendto g_real_sendto = NULL;
static pfn_bind g_real_bind = NULL;
static uint32_t g_target_ip = 0; // Network byte order

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
    return ip;
  }
  return 0;
}

static uint32_t load_target_ip(void) {
  char buf[128] = {0};

  // 1. Environment Variable check
  if (GetEnvironmentVariableA("BIFLOW_TARGET_IP", buf, sizeof(buf)) > 0) {
    uint32_t ip = parse_ip_string(buf);
    if (ip != 0) {
      return ip;
    }
  }

  // 2. User Temp File check (%TEMP%\biflow_target_ip.txt)
  char temp_path[MAX_PATH];
  if (GetTempPathA(MAX_PATH, temp_path) > 0) {
    strcat_s(temp_path, MAX_PATH, "biflow_target_ip.txt");
    FILE *f = NULL;
    if (fopen_s(&f, temp_path, "r") == 0 && f) {
      if (fgets(buf, sizeof(buf), f)) {
        fclose(f);
        uint32_t ip = parse_ip_string(buf);
        if (ip != 0) {
          return ip;
        }
      } else {
        fclose(f);
      }
    }
  }

  // 3. System ProgramData File check (%ProgramData%\BiFlow\target_ip.txt)
  char prog_data[MAX_PATH];
  if (GetEnvironmentVariableA("ProgramData", prog_data, sizeof(prog_data)) > 0) {
    char target_file[MAX_PATH];
    sprintf_s(target_file, sizeof(target_file), "%s\\BiFlow\\target_ip.txt",
              prog_data);
    FILE *f = NULL;
    if (fopen_s(&f, target_file, "r") == 0 && f) {
      if (fgets(buf, sizeof(buf), f)) {
        fclose(f);
        uint32_t ip = parse_ip_string(buf);
        if (ip != 0) {
          return ip;
        }
      } else {
        fclose(f);
      }
    }
  }

  return 0;
}

static void bind_socket_if_needed(SOCKET s) {
  if (g_target_ip == 0) {
    g_target_ip = load_target_ip();
    if (g_target_ip == 0)
      return;
  }

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
  if (name && namelen >= (int)sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)name;
    // Only redirect outbound client sockets that bind to INADDR_ANY on port 0
    if (in->sin_family == AF_INET && in->sin_addr.s_addr == INADDR_ANY &&
        in->sin_port == 0) {
      if (g_target_ip == 0) {
        g_target_ip = load_target_ip();
      }
      if (g_target_ip != 0) {
        struct sockaddr_in redirected;
        memcpy(&redirected, in, sizeof(redirected));
        redirected.sin_addr.s_addr = g_target_ip;
        if (g_real_bind) {
          return g_real_bind(s, (struct sockaddr *)&redirected,
                             sizeof(redirected));
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
    bind_socket_if_needed(s);
  }
  return g_real_connect(s, name, namelen);
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name,
                                  int namelen, LPWSABUF lpCallerData,
                                  LPWSABUF lpCalleeData, LPQOS lpSQOS,
                                  LPQOS lpGQOS) {
  if (name && name->sa_family == AF_INET) {
    bind_socket_if_needed(s);
  }
  return g_real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData,
                           lpSQOS, lpGQOS);
}

static int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
                              const struct sockaddr *to, int tolen) {
  if (to && to->sa_family == AF_INET) {
    bind_socket_if_needed(s);
  }
  return g_real_sendto(s, buf, len, flags, to, tolen);
}

static void init_hooks(void) {
  g_target_ip = load_target_ip();
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
