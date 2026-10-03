# ⚡ BiFlow

<p align="center">
  <img src="assets/biflow_icon.jpg" alt="BiFlow Logo" width="130" style="border-radius: 20px;" />
</p>

<p align="center">
  <strong>Portable Windows Per-Application Split Routing & Network Isolation Engine</strong>
</p>

<p align="center">
  <a href="https://github.com/PishiKuchulu/BiFlow/actions/workflows/build-release.yml"><img src="https://img.shields.io/github/actions/workflow/status/PishiKuchulu/BiFlow/build-release.yml?branch=main&style=flat-square&logo=github&label=Build" alt="CI Status" /></a>
  <a href="https://github.com/PishiKuchulu/BiFlow/releases"><img src="https://img.shields.io/github/v/release/PishiKuchulu/BiFlow?style=flat-square&color=38bdf8" alt="Release" /></a>
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(x64)-blue?style=flat-square&logo=windows" alt="Platform" />
  <img src="https://img.shields.io/badge/Language-Rust%20%7C%20Win32%20C-orange?style=flat-square&logo=rust" alt="Rust" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" /></a>
</p>

---

## 📖 Overview

When a VPN or proxy tunnel is active on Windows, all system traffic is typically encapsulated within the tunnel. **BiFlow** gives you fine-grained control over your network topology:

It allows you to route designated applications **directly through your physical network adapter** (e.g. Wi-Fi or Ethernet), while keeping the rest of your operating system traffic protected inside the VPN tunnel.

```
                           ┌───────────────────────────────┐
                           │      Windows Workstation      │
                           └───────────────┬───────────────┘
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 ▼                                                   ▼
     [ Standard Applications ]                             [ Bypassed Applications ]
   (Browser, Telegram, Discord)                              (Steam, Games, Torrents)
                 │                                                   │
                 ▼                                                   ▼
       ┌───────────────────┐                              ┌─────────────────────┐
       │ VPN / Tunnel NIC  │                              │ BiFlow Winsock Hook │
       └─────────┬─────────┘                              └──────────┬──────────┘
                 │                                                   │
                 ▼                                                   ▼
         (Encrypted Path)                                    (Direct Local Path)
       ┌───────────────────┐                              ┌─────────────────────┐
       │   VPN Gateway     │                              │ Physical LAN / Wi-Fi│
       └───────────────────┘                              └─────────────────────┘
```

---

## ✨ Key Features

- **🚀 100% Driverless & Portable:** No virtual network adapter drivers (TAP/TUN), no WinDivert drivers, and no risk of Blue Screens (BSOD). Runs as a single portable standalone executable (`BiFlow.exe`).
- **⚡ Winsock Socket Interception:** Intercepts client socket operations at the native Windows Sockets layer (`connect`, `WSAConnect`, `sendto`, and `bind` for `ConnectEx`) using an embedded high-performance hook DLL.
- **🌐 0ms Win32 Hardware Discovery:** Blazing-fast discovery of network adapters, gateways, and connection statuses via Win32 `GetAdaptersAddresses` API with zero PowerShell or WMI delays.
- **📊 Real-time Network Telemetry:** Live detection of running GUI applications and processes actively exchanging packets over IPv4/IPv6 using extended TCP/UDP MIB tables.
- **🛡️ One-Click Internet Kill-Switch:** Instantly isolate any application from the internet using native Windows Defender Firewall rules and sever existing TCP connections on the spot via `SetTcpEntry`.
- **🚀 Direct Launch Mode:** Launch games and applications directly from BiFlow with the bypass hook pre-injected before the application makes its first network call.
- **📋 Smart Profiles:** Save configurations (Default, Gaming, Streaming, Work) with per-profile adapter selections, live rule modification detection, and one-click revert.
- **🗕 System Tray Integration:** Docks into the Windows notification area with background watchdog monitoring, minimize-to-tray, and an instant-restore context menu.
- **🔒 UAC-Safe Elevated Autostart:** Seamless integration with Windows Task Scheduler (`schtasks`) to ensure automatic startup with Administrator privileges without being silenced by Windows UAC.

---

## 🚀 Quick Start

### 1. Download
Download the latest standalone executable from [Releases](https://github.com/PishiKuchulu/BiFlow/releases):
- `BiFlow.exe` (Single Portable Binary)
- `BiFlow-Portable-Windows-x64.zip` (Portable Archive)

### 2. Usage
1. Connect your VPN client (WireGuard, OpenVPN, v2ray, Sing-box, Tailscale, Clash, etc.).
2. Launch **`BiFlow.exe`** (Run as Administrator to allow firewall management and cross-process injection).
3. Under the **🌐 Network Adapters** tab, verify that your physical network adapter (Wi-Fi or Ethernet) is selected.
4. Under the **📱 Applications** tab, find your application (or click **Browse `.exe`** to add any portable program).
5. Click **⚡ Enable Direct Bypass** or **🚀 Launch Direct**.
6. That's it! Your selected application now communicates directly over your physical network adapter.

---

## 🛠️ Architecture & Under the Hood

BiFlow achieves reliable, driver-free per-process split-routing through a multi-tiered architecture:

| Component | Technology | Responsibility |
| :--- | :--- | :--- |
| **Frontend UI** | Rust 2021 + `egui` / `eframe` | Clean dark-mode UI, reactive state management, profile persistence |
| **Adapter Telemetry** | Win32 `IP Helper` API | Querying interface table, identifying virtual/VPN adapters |
| **Connection Monitor** | Win32 `MIB_TCPTABLE` / `UDPTABLE` | Identifying PIDs with open sockets and tearing down blocked TCP streams |
| **Injection Engine** | Win32 Toolhelp + `CreateRemoteThread` | Safe injection of 64-bit hook DLL into target process address space |
| **Hook Core** | Native C + `MinHook` | Intercepting `ws2_32.dll` to bind outbound client sockets to physical adapter IP |
| **Firewall Engine** | Windows Defender Firewall | Inbound & Outbound block rules with fallback to PowerShell NetSecurity |
| **Scheduler** | Windows Task Scheduler (`schtasks`) | Highest-privilege execution on Windows user logon |

---

## 🔨 Building from Source

### Prerequisites
- **Operating System:** Windows 10 or Windows 11 (64-bit)
- **Rust Toolchain:** Stable MSVC toolchain (`x86_64-pc-windows-msvc`)
- **C++ Build Tools:** Visual Studio C++ Build Tools or MSVC compiler (`cl.exe`)

### Quick Build
Clone the repository:
```powershell
git clone https://github.com/PishiKuchulu/BiFlow.git
cd BiFlow
```

Compile release binary:
```powershell
cargo build --release
```

Or run the automated release builder script:
```powershell
.\scripts\build-release.ps1
```

The resulting standalone executable will be created at:
```
BiFlow.exe
```

---

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are very welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.
