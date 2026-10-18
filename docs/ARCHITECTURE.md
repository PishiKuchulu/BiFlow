# BiFlow Architecture

BiFlow is a high-performance, portable Windows per-application split routing and network isolation utility built in Rust with native Win32 API integration and a high-performance Winsock interception hook DLL.

## 1. Architectural Layers

### A. UI and State Management (Rust / egui)
- **GUI Engine:** Powered by `eframe` and `egui` (v0.33) with a custom dark theme.
- **State & Profiles:** Managed in `AppState` ([src/app/mod.rs](../src/app/mod.rs)). Configurations, custom apps, and profile rules (Default, Gaming, etc.) are persisted to `biflow_config.json`.
- **System Tray:** Integrated via `tray-icon` ([src/windows/tray.rs](../src/windows/tray.rs)) with instant restore and menu event dispatching.

### B. Network Discovery & Telemetry (Win32 APIs)
- **Adapter Enumeration:** Uses Win32 `GetAdaptersAddresses` API ([src/network/mod.rs](../src/network/mod.rs)) to discover physical and VPN/virtual adapters with zero subprocess/PowerShell latency.
- **Active Network Telemetry:** Queries `GetExtendedTcpTable` and `GetExtendedUdpTable` to identify active PIDs communicating over IPv4/IPv6.
- **Active Connection Teardown:** Uses `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB` to sever existing connections instantly when an application is blocked.

### C. Direct Split-Routing Engine (Winsock Interception)
- **Mechanism:** When bypass is activated for a target application, `BiFlow` injects an embedded 64-bit hook DLL (`biflow_hook64.dll`) into the target process via `CreateRemoteThread` + `LoadLibraryW`.
- **Hook Layer:** Inside the target process, MinHook intercepts Winsock 2 (`ws2_32.dll`) APIs:
  - `connect` / `WSAConnect`: Checks if the socket is unbound (`INADDR_ANY`), and automatically binds it to the physical adapter IP.
  - `bind`: Intercepts client sockets binding to port 0 with `INADDR_ANY` (used by asynchronous APIs such as `ConnectEx`) and redirects them to the direct physical adapter IP.
  - `sendto` / `WSASendTo`: Ensures UDP datagrams are bound to the direct physical interface IP.
- **IP Target Distribution:**
  1. `BIFLOW_TARGET_IP` environment variable (bootstrap for child processes spawned by BiFlow, read once at DLL attach).
  2. `%TEMP%\biflow_target_ip.txt` (for per-user live injection).
  3. `%ProgramData%\BiFlow\target_ip.txt` (cross-user/cross-session global fallback).
- **Policy freshness:** The hook fingerprints the policy files (last-write time) on every intercepted call. Deleting the files ("Disable All" / "Exit" / removing the last bypass) disables the bypass for *new* sockets in already-injected processes; rewriting them (profile switch, adapter change) applies the new target IP without reinjection. Already-established connections are never migrated.
- **Per-app allow-list:** BiFlow also maintains `bypass_apps.txt` (same two locations) with the full paths of bypassed executables. The hook compares its own process path against the list, so removing one app stops its bypass while other apps keep theirs.

### D. Internet Isolation & Firewall Engine
- Outbound and Inbound rules are dynamically added/removed in Windows Defender Firewall (`netsh advfirewall firewall` with PowerShell `New-NetFirewallRule` fallback).
- Active TCP connections for the blocked process are terminated on the spot using `SetTcpEntry`.

### E. Elevated Autostart
- Leverages Windows Task Scheduler (`schtasks.exe /Create /TN BiFlow /SC ONLOGON /RL HIGHEST`) to allow the elevated executable to launch automatically at logon without being dropped by Windows UAC.

## 2. Scope & Safety
- **Clean Teardown:** When disabled or closed, target IP files are removed (the injected hook treats missing files as "disabled" for new sockets), firewall rules are cleared, and the in-memory bypass registry is emptied. Note: already-established connections in injected processes are not migrated; restart the app for a fully clean state.
- **Architecture Compatibility:** Targets 64-bit (x64) Windows applications. 32-bit (WOW64) processes are detected and skipped to prevent injection faults.
