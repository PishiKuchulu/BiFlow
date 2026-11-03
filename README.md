# ⚡ BiFlow / بای‌فلو

**Portable Windows Per-Application Split Routing & Network Isolation Engine**  
**موتور مسیریابی تفکیک‌شده و ایزولاسیون شبکه برای هر برنامه در ویندوز (بدون نیاز به درایور)**

---

## 🇬🇧 English

When a VPN or proxy tunnel is active on Windows, all system traffic is typically encapsulated within the tunnel, killing your ping in games or slowing down local network tasks. **BiFlow** gives you absolute control over your network topology.

It allows you to route designated applications (like Steam, Games, or Torrent clients) **directly through your physical network adapter** (Wi-Fi/Ethernet), while keeping the rest of your operating system traffic protected inside the encrypted VPN tunnel.

### 🌐 The BiFlow Architecture

```text
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

### ✨ Key Features

* 🚀 **100% Driverless & Portable:** No virtual network adapter drivers (TAP/TUN), no WinDivert drivers, and no kernel code at all — so there is no driver that could cause a Blue Screen (BSOD). Runs as a single portable standalone executable (`BiFlow.exe`).
* ⚡ **Native Winsock Interception:** Intercepts client socket operations at the native Windows Sockets layer (`bind`, `connect`, `WSAConnect`, `sendto`, `WSASendTo`) using an embedded high-performance hook DLL.
* 🌐 **Native Hardware Discovery:** Network adapters and gateways are enumerated directly through the native Win32 `GetAdaptersAddresses` API — no PowerShell or WMI delays.
* 📊 **Open-Connection Telemetry:** Live snapshot of running GUI applications and their open IPv4/IPv6 connections (a socket snapshot, not a traffic meter).
* 🛡️ **One-Click Block:** Instantly cut any application off from new connections using native Windows Defender Firewall rules (both directions, verified after creation), and terminate its existing IPv4 TCP connections on the spot via `SetTcpEntry`. Existing IPv6 connections end on their own; new ones are blocked.
* 🎮 **Direct Launch Mode:** Launch games and applications directly from BiFlow with the bypass hook pre-injected *before* the application makes its first network call.
* 📋 **Smart Profiles:** Save rule sets (Gaming, Streaming, Work) and switch between them with one click. The Direct adapter choice is global and kept separate from profiles.
* 🗕 **System Tray Integration:** Docks into the Windows notification area with background watchdog monitoring.
* 🔒 **UAC-Safe Autostart:** Starts automatically at Windows logon via Task Scheduler with Administrator privileges and no UAC prompts — provided `BiFlow.exe` lives in a protected location (e.g. Program Files), which BiFlow verifies before registering the task.

### 📲 Download & Usage

1. Go to the [Releases](https://github.com/PishiKuchulu/BiFlow/releases) page.
2. Download the latest `BiFlow-Portable-Windows-x64.zip` (or the standalone `BiFlow.exe`).
3. Extract it anywhere on your PC and run `BiFlow.exe` as Administrator.
4. Select the apps you want to bypass the VPN and enjoy the direct connection!

Optional: verify your download against the `SHA256SUMS.txt` published with each release.

### 📚 Documentation

* [Architecture](docs/ARCHITECTURE.md) • [Networking](docs/NETWORKING.md) • [Security model](docs/SECURITY.md) • [Known limitations](docs/LIMITATIONS.md)
* Note: the bypass core targets IPv4; see the limitations document for the exact scope.
* License: MIT — see [LICENSE](LICENSE).

---

## 🇮🇷 فارسی

وقتی یک VPN یا پروکسی در ویندوز روشن است، معمولاً تمام ترافیک سیستم از داخل تونل عبور می‌کند؛ اتفاقی که باعث افزایش پینگ در بازی‌ها یا کندی کارهای شبکه محلی می‌شود. **بای‌فلو (BiFlow)** کنترل کامل توپولوژی شبکه را به شما برمی‌گرداند.

این برنامه به شما اجازه می‌دهد ترافیک برنامه‌های خاص (مثل استیم، بازی‌های آنلاین یا نرم‌افزارهای دانلود تورنت) را **مستقیماً از طریق کارت شبکه فیزیکی** (وای‌فای یا کابل LAN) عبور دهید، در حالی که ترافیک سایر بخش‌های ویندوز به صورت امن و رمزنگاری‌شده در تونل VPN باقی می‌ماند.

### ✨ ویژگی‌های کلیدی

* 🚀 **۱۰۰٪ پرتابل و بدون درایور:** برخلاف ابزارهای مشابه، نیازی به نصب درایورهای مجازی (TAP/TUN) یا WinDivert ندارد و هیچ کد سطح کرنلی اجرا نمی‌کند؛ پس درایوری وجود ندارد که باعث صفحه آبی مرگ (BSOD) شود. فقط یک فایل اجرایی (`BiFlow.exe`) است!
* ⚡ **هوک سطح پایین Winsock:** عملیات سوکت را در لایه بومی ویندوز (`bind`، `connect`، `WSAConnect`، `sendto`، `WSASendTo`) با استفاده از یک DLL سریع رهگیری و مسیریابی می‌کند.
* 🌐 **شناسایی بومی سخت‌افزار:** آداپتورهای شبکه و گیت‌وی‌ها مستقیماً از طریق API بومی Win32 یعنی `GetAdaptersAddresses` خوانده می‌شوند؛ بدون اسکریپت‌های کند PowerShell و WMI.
* 📊 **تله‌متری کانکشن‌های باز:** نمای لحظه‌ای از برنامه‌های در حال اجرا و کانکشن‌های باز IPv4/IPv6 آن‌ها (نمای سوکت‌های باز است، نه شمارندهٔ ترافیک).
* 🛡️ **قطع فوری با یک کلیک:** همهٔ کانکشن‌های جدید هر برنامه را در هر دو جهت با فایروال خودِ ویندوز Defender ببندید (قانون‌ها بعد از ساخت راستی‌آزمایی می‌شوند) و کانکشن‌های TCP موجود IPv4 آن را بلافاصله با `SetTcpEntry` خاتمه دهید. کانکشن‌های IPv6 موجود خودشان پایان می‌یابند و کانکشن جدیدشان بلاک است.
* 🎮 **حالت Direct Launch:** بازی‌ها را مستقیماً از داخل BiFlow اجرا کنید تا هوکِ بای‌پس **قبل از اولین درخواست شبکه** به پروسس بازی تزریق شود.
* 📋 **پروفایل‌های هوشمند:** مجموعه‌قانون‌های مختلف (گیمینگ، استریم، کار) را ذخیره کنید و با یک کلیک بین آن‌ها جابه‌جا شوید. انتخاب آداپتور مستقیم سراسری است و جدا از پروفایل‌ها نگه داشته می‌شود.
* 🗕 **حضور در System Tray:** اجرای آرام در پس‌زمینه و نظارت مداوم (Watchdog) روی وضعیت شبکه.
* 🔒 **اجرای خودکار بدون دردسر UAC:** اجرای خودکار هنگام ورود به ویندوز (Logon) با Task Scheduler و دسترسی ادمین، بدون نمایش پنجره‌های آزاردهنده UAC — به این شرط که فایل `BiFlow.exe` در یک مکان محافظت‌شده (مثل Program Files) باشد؛ BiFlow این شرط را پیش از ثبت تسک بررسی می‌کند.

### 📲 دانلود و استفاده

۱. به بخش [Releases](https://github.com/PishiKuchulu/BiFlow/releases) در همین صفحه بروید.
۲. آخرین نسخهٔ `BiFlow-Portable-Windows-x64.zip` (یا فایل تکی `BiFlow.exe`) را دانلود کنید.
۳. فایل را در هر جایی از سیستم Extract کرده و `BiFlow.exe` را با دسترسی Administrator اجرا کنید.
۴. برنامه‌هایی که می‌خواهید از VPN رد شوند (Bypass) را انتخاب کنید و از سرعت کامل اینترنت لذت ببرید!

اختیاری: دانلودتان را با فایل `SHA256SUMS.txt` که همراه هر ریلیز منتشر می‌شود تطبیق دهید.

### 📚 مستندات

* [معماری](docs/ARCHITECTURE.md) • [شبکه](docs/NETWORKING.md) • [مدل امنیتی](docs/SECURITY.md) • [محدودیت‌های شناخته‌شده](docs/LIMITATIONS.md)
* توجه: هستهٔ بای‌پس IPv4 را هدف می‌گیرد؛ دامنهٔ دقیق در سند محدودیت‌ها آمده است.
* مجوز: MIT — فایل [LICENSE](LICENSE) را ببینید.

---

**Developed with ❤️ by Farzad Sholeh**
