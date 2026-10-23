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
- **Active Connection Teardown:** Uses `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB` to sever existing IPv4 TCP connections instantly when an application is blocked. (IPv6 connections cannot be terminated this way — `SetTcpEntry` only accepts the IPv4 row layout — so IPv6 is stopped by the firewall rule for new connections instead.)

### C. Direct Split-Routing Engine (Winsock Interception)
- **Mechanism:** When bypass is activated for a target application, `BiFlow` injects an embedded 64-bit hook DLL (`biflow_hook64.dll`) into the target process via `CreateRemoteThread` + `LoadLibraryW`.
- **Hook Layer:** Inside the target process, MinHook intercepts Winsock 2 (`ws2_32.dll`) APIs:
  - `connect` / `WSAConnect`: Checks if the socket is unbound (`INADDR_ANY`), and automatically binds it to the physical adapter IP.
  - `bind`: Intercepts client sockets binding to port 0 with `INADDR_ANY` (used by asynchronous APIs such as `ConnectEx`) and redirects them to the direct physical adapter IP.
  - `sendto` / `WSASendTo`: Ensures UDP datagrams are bound to the direct physical interface IP.
- **IP Target Distribution:**
  1. `%ProgramData%\BiFlow\target_ip.txt` (authoritative; the directory's DACL is admin-write-only). The `BIFLOW_TARGET_IP` environment variable is no longer used (it leaked into every child process BiFlow spawned).
  2. `%TEMP%\biflow_target_ip.txt` (legacy fallback, read only when the ProgramData copy is absent).
- **Policy freshness:** The hook fingerprints the policy files (last-write time) at most every 250 ms. Deleting the files ("Disable All" / "Exit" / removing the last bypass) disables the bypass for *new* sockets in already-injected processes; rewriting them (profile switch, adapter change, or the watchdog noticing that the adapter's IPv4 changed after a DHCP renewal) applies the new target IP without reinjection. Already-established connections are never migrated.
- **Per-app allow-list:** BiFlow also maintains `bypass_apps.txt` (same two locations) with the full paths of bypassed executables. The hook compares its own process path against the list, so removing one app stops its bypass while other apps keep theirs.

### D. Internet Isolation & Firewall Engine
- Outbound and Inbound rules are dynamically added/removed in Windows Defender Firewall (`netsh advfirewall firewall` with PowerShell `New-NetFirewallRule` fallback).
- Active TCP connections for the blocked process are terminated on the spot using `SetTcpEntry`.

### E. Elevated Autostart
- Leverages Windows Task Scheduler with an XML task definition (current user only, `HighestAvailable`, no battery stop, no execution time limit, `--minimized` so BiFlow starts in the tray) to allow the elevated executable to launch automatically at logon without being dropped by Windows UAC.

## 2. Scope & Safety
- **Clean Teardown:** When disabled or closed, the policy files are removed (the injected hook treats missing files as "disabled" for new sockets) and the in-memory bypass registry is emptied. Firewall **block** rules are intentionally NOT removed on exit — blocking is a persistent user decision and is only undone by "Unblock" in the app. Note: already-established connections in injected processes are not migrated; restart the app for a fully clean state.
- **Architecture Compatibility:** Targets 64-bit (x64) Windows applications. 32-bit (WOW64) processes are detected and skipped to prevent injection faults.
