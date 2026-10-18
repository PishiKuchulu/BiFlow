# Security

BiFlow is a local, single-user Windows tool. It performs no telemetry and makes
no network connections of its own.

## What BiFlow actually does (and why it needs Administrator)

- **DLL injection (documented, user-initiated only):** when you enable a bypass,
  BiFlow injects `biflow_hook64.dll` into the target application's process via
  `CreateRemoteThread` + `LoadLibraryW`. Injection only ever targets processes
  you explicitly selected, plus 64-bit safety checks (WOW64 processes are
  skipped). There is no silent/background injection.
- **Winsock hooking:** the injected DLL intercepts `connect` / `WSAConnect` /
  `sendto` / `WSASendTo` / `bind` in `ws2_32.dll` to bind outbound IPv4 sockets
  to the selected physical adapter's IP. No traffic content is read, logged, or
  modified.
- **Windows Defender Firewall rules:** "Block Internet" creates per-application
  inbound+outbound block rules named `BiFlow_Block_<id>`. Only rules with that
  prefix are ever removed by the app (including orphan cleanup).
- **Autostart (opt-in):** creates a Scheduled Task (`\BiFlow`, highest
  privileges) and/or an `HKCU\...\Run` value. Both are removed when you disable
  the option.
- **No WFP, no drivers, no antivirus/firewall disabling.** BiFlow does not
  install drivers, does not touch the Windows Filtering Platform, and never
  disables security products. A VPN kill-switch that blocks direct egress will
  still block bypassed traffic — BiFlow does not circumvent it.

## Trust boundaries

- The hook DLL is embedded in `BiFlow.exe` and extracted to
  `%TEMP%\BiFlow\biflow_hook64.dll` (size-checked before write). The policy
  files it reads (`%TEMP%\biflow_target_ip.txt`,
  `%ProgramData%\BiFlow\target_ip.txt`, and the `bypass_apps.txt`
  allow-lists) are written by the elevated BiFlow process; standard users can
  read but not modify them.
- BiFlow only ever injects into processes **you** chose. Anyone with
  Administrator rights on the machine can already do all of this without BiFlow.
- Chromium-based browsers launched via "Launch Direct" run with
  `--disable-features=RendererCodeIntegrity --no-proxy-server`, which weakens
  the browser's sandbox code-integrity check. This is required for the hook to
  load and is disclosed in the UI when launching such browsers.

Only run BiFlow on machines you own or administer.
