# Changelog

## v0.3.0 — 2026-10-23

Full fix pass over an external line-by-line review (42 findings). Highlights:

### Security
- **SEC-01** Hook DLL and policy files moved out of `%TEMP%` into
  `%ProgramData%\BiFlow` with a protected admin-only DACL; the DLL is
  version-named and verified byte-for-byte before every injection; the hook
  treats the ProgramData policy as authoritative (TEMP is legacy fallback).
- **SEC-02** `SeDebugPrivilege` is no longer enabled at startup.
- **SEC-03** README/SECURITY now carry explicit unsigned-binary, antivirus
  and anti-cheat (account ban) warnings; releases ship `SHA256SUMS.txt`.
- **FW-02** Removed the fixed-name `%TEMP%\biflow_fw_batch.cmd` elevated
  batch path (TOCTOU). Non-elevated firewall operations now fail honestly.
- **APP-01** "Launch Direct" starts apps with the shell's medium-integrity
  token (not Administrator) whenever possible; failure to inject now
  terminates the suspended process instead of leaving an un-bypassed copy
  running, and an already-running instance is called out in the status line.

### Hook (cpp/biflow_hook.c)
- **HOOK-01** `Hook_bind` falls back to the app's original bind when the
  redirected bind fails (stale adapter IP); the watchdog republishes the
  policy when the selected adapter's IPv4 changes (DHCP/Wi-Fi).
- **HOOK-02** The `bind` redirect now applies only to TCP stream sockets;
  UDP listeners/discovery sockets are no longer re-bound.
- **HOOK-03** All path/file handling uses the wide APIs and the allow-list
  is decoded as UTF-8 — non-ASCII (e.g. Persian) user names and install
  paths now bypass correctly.
- **HOOK-04** Hook installation moved out of `DllMain` (loader lock) onto
  an init thread; detach is a no-op during process termination.
- **HOOK-05** Policy paths are built once; policy revalidation is
  throttled to 250 ms with cached paths.
- **HOOK-06** Policy state is snapshotted under an SRWLOCK (no torn reads).
- **HOOK-07** Loopback, link-local, multicast, broadcast and unspecified
  destinations are never re-bound.
- **HOOK-08** The connect path no longer depends on `getsockname` of an
  unbound socket; it attempts the bind and ignores the (expected) failure
  for already-bound sockets.
- **HOOK-09** The hook DLL is built with a static CRT (`/MT`).
- **APP-02** The DLL writes `hook_status_<pid>.txt`; "Live" in the UI now
  requires the DLL's own confirmation that all 5 hooks are installed.

### App / enforcement / network
- **ENF-02** Enforcement runs on a dedicated background watchdog thread;
  the UI thread no longer scans processes or blocks on injection.
- **INJ-02** Versioned DLL file names end the "locked stale DLL" failure.
- **INJ-03** Watchdog also covers same-directory descendants of a
  bypassed app (launcher helpers); injected PIDs are keyed by process
  creation time, so recycled PIDs are never mistaken for injected ones.
- **INJ-04** Chromium flag detection matches exact file names
  (`chrome.exe` / `msedge.exe` / `brave.exe`) only.
- **ENF-01** Stale policy/status files from a crashed run are cleared at
  startup before profile rules are re-applied.
- **FW-01** Unblock verifies the rule is actually gone; startup no longer
  deletes/recreates persistent firewall rules — only missing ones are made.
- **FW-03** Removed the invalid IPv6 `SetTcpEntry` cast (it never worked);
  docs now state IPv6 teardown honestly.
- **NET-01** Adapters are remembered by GUID (not the unstable IfIndex);
  best-adapter selection requires a default gateway and a non-APIPA IPv4;
  Hyper-V/VMware/VirtualBox/Bluetooth adapters are excluded; `tap`/`tun`
  match as whole tokens.
- **CFG-01** Config save is now atomic (write tmp + rename-replace +
  fsync); an unreadable config at startup disables saving instead of being
  overwritten by defaults; all Store fields have serde defaults.
- **APP-03** Single-instance mutex; a second launch focuses the first.
- **APP-04** Autostart is one XML-defined Scheduled Task: current user
  only, not stopped on battery, no 72 h limit, `--minimized` start, and
  honest failure reporting.
- **UI-01** Per-app running/network status is cached per refresh instead
  of being recomputed for every app on every frame.
- **LOW-01..13** Directory-prefix boundary fix in network matching;
  adapter table queries retry with aligned buffers and count only
  ESTABLISHED TCP connections as "active"; discovery picks the main exe by
  display-name match instead of first-in-folder; tray Exit is handled by
  the main thread; Disable All offers "Resume Bypasses"; human-readable
  log timestamps; dead `EnforcementStatus` removed; repo cleanup
  (agent plan doc, duplicate icon, unused `.res`/JPEG removed).

### Build / CI
- **BLD-01** `build.rs` keys off `CARGO_CFG_TARGET_OS` (not the host),
  builds the hook DLL into `OUT_DIR` with `/Fo` there too, lists every
  MinHook source in `rerun-if-changed`, and applies the UAC manifest only
  to the binary (`rustc-link-arg-bins`) so `cargo test` works unelevated.
- **LOW-11** CI: `--locked` builds/tests, informational fmt/clippy steps,
  workflow permissions split (read by default, write only in the release
  job), no recursive-submodule checkout, `SHA256SUMS.txt` published with
  releases.

Known remaining limits are documented in `docs/LIMITATIONS.md`.

## v0.2.2 — 2026-10-18

- Fixed the CI hook-DLL build (MSVC developer environment step; build.rs
  now propagates the compiler environment and fails loudly).

## v0.2.1 — 2026-10-18

- Honest disable/teardown, hook policy refresh, WSASendTo hook, IPv6
  teardown attempt, firewall/full-path matching fixes, doc corrections.

## v0.2.0 — 2026-10-18

- Initial release.
