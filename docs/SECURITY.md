# Security

BiFlow is a local, single-user Windows tool. It performs no telemetry and makes
no network connections of its own.

## What BiFlow actually does (and why it needs Administrator)

- **DLL injection (explicit apps, automatic watchdog):** when you enable a
  bypass for an app, BiFlow injects `biflow_hook64.dll` into that app's
  processes via `CreateRemoteThread` + `LoadLibraryW`. Injection only ever
  targets processes whose executable you selected (matched by full path),
  their same-directory descendants, and processes of those apps that start
  later — a background watchdog thread re-checks every ~1.5 s and injects
  newly started processes of bypassed apps automatically. That automation is
  part of the feature (it is how a bypass survives an app restart); it is
  never applied to apps you did not select. 64-bit safety checks apply
  (WOW64 processes are skipped).
- **Winsock hooking:** the injected DLL intercepts `connect` / `WSAConnect` /
  `sendto` / `WSASendTo` / `bind` in `ws2_32.dll` to bind outbound IPv4 sockets
  to the selected physical adapter's IP. No traffic content is read, logged, or
  modified. After loading, the DLL reports how many hooks it installed back to
  BiFlow; the UI only shows a bypass as "live" when the DLL confirms all
  5 hooks are active.
- **Windows Defender Firewall rules:** "Block Internet" creates per-application
  inbound+outbound block rules named `BiFlow_Block_<id>`. Only rules with that
  prefix are ever removed by the app (including orphan cleanup).
- **Autostart (opt-in):** creates a single Scheduled Task (`\BiFlow`,
  highest privileges, current user only, started minimized to the tray,
  not stopped on battery, no execution time limit). It is removed when you
  disable the option.
- **Launched apps are NOT elevated:** "Launch Direct" starts the target app
  with the shell's (explorer.exe) medium-integrity token whenever possible,
  so browsers and games do not run as Administrator just because BiFlow does.
  If that is impossible on a given system, BiFlow falls back to an elevated
  launch and says so in the status line.
- **No `SeDebugPrivilege`, no WFP, no drivers, no antivirus/firewall
  disabling.** BiFlow does not install drivers, does not touch the Windows
  Filtering Platform, and never disables security products. A VPN kill-switch
  that blocks direct egress will still block bypassed traffic — BiFlow does
  not circumvent it.

## Trust boundaries

- The hook DLL is embedded in `BiFlow.exe` and extracted to
  `%ProgramData%\BiFlow\bin\biflow_hook64_v<version>.dll`. Before every use
  its full content is compared byte-for-byte against the embedded copy.
  The `%ProgramData%\BiFlow` directory and its security-critical children
  get a protected DACL **and** their owner is set to Administrators (both
  verified after setting): SYSTEM and Administrators have full control;
  standard users can only read and execute. Setting the owner matters —
  an object's owner implicitly holds WRITE_DAC, so a DACL alone would
  still let whoever created the folder rewrite its ACL. A non-elevated
  process therefore cannot swap the DLL that the elevated BiFlow injects
  into other processes. (The content check and the subsequent
  `LoadLibraryW` remain separate path-based operations; the owner + DACL
  protection is what makes that window unusable to a non-elevated
  process.)
- The policy files the hook reads (`target_ip.txt`, `bypass_apps.txt`) live
  in the same protected directory and are authoritative there. There is no
  `%TEMP%` policy copy: legacy TEMP copies left by old versions are
  deleted during cleanup, never written and never read.
- Hook status reports (`hook_status_<pid>.txt`) live in a `status`
  subfolder whose DACL additionally grants standard users write access:
  the hook runs inside target processes with the user's normal token and
  must be able to report, which the policy folder's read-only ACL made
  impossible. A status report is advisory only — a same-user process
  could in principle plant one — so BiFlow deletes any stale report for a
  PID before injecting and never treats a report as policy.
- The configuration file and the diagnostic log live in the user's own data
  folder (`%LOCALAPPDATA%\BiFlow`, or `data\` next to the executable for a
  portable copy) WITHOUT an ACL boundary: any process running as the same
  user can read or edit them. The log therefore contains no secrets (it does
  contain executable paths, local IPs and PIDs — treat it like any diagnostic
  file before sharing it). Because the config is same-user-writable input,
  the loader validates it: rules must reference absolute executable paths,
  duplicate rules are merged, and a corrupt or newer-version config is
  preserved as a `.corrupt` copy with saving disabled rather than silently
  reset. Since v0.3.3 the autostart gate also verifies the executable
  directory's real DACL (not just its path prefix) before registering the
  elevated logon task, and the task's principal is the current user's SID
  taken from the process token.
- BiFlow only ever injects into processes of apps **you** chose. Anyone with
  Administrator rights on the machine can already do all of this without BiFlow.
- Chromium-based browsers launched via "Launch Direct" run with
  `--disable-features=RendererCodeIntegrity --no-proxy-server`, which weakens
  the browser's sandbox code-integrity check. This is required for the hook to
  load and is disclosed in the UI when launching such browsers.

## Antivirus and anti-cheat — read this first

BiFlow is **not code-signed**, and its core technique (DLL injection into
other processes) is behaviorally similar to some malware. Expect Windows
SmartScreen warnings on first run and possible antivirus heuristics. Only
download BiFlow from this repository's Releases page and verify the
published SHA-256 checksums (`SHA256SUMS.txt`).

**Do not use BiFlow with games protected by kernel anti-cheat systems**
(Easy Anti-Cheat, BattlEye, Vanguard, etc.). Injecting any DLL into such a
game can get your account banned. BiFlow does not attempt to evade
anti-cheat detection, and no bypass is worth a banned account.

Only run BiFlow on machines you own or administer.
