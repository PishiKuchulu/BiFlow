# Changelog

## v0.3.4 — 2026-11-03

Fix wave from the round-2 granular audit of v0.3.3 (46 new findings:
0 Critical / 2 High / 18 Medium / 25 Low / 1 Info). The audit also
re-verified every v0.3.3 fix claim: 33 of 37 fully verified, none
missing or fake — the three caveats were defects in the v0.3.3 fix wave
itself, and all three are fixed here.

Correctness (engine):
- A transient adapter-enumeration failure during a manual Refresh
  could empty the adapter list and make the watchdog suspend every
  bypass after two cycles. refresh() is now fail-soft like the other
  two adapter consumers: on error/empty it keeps the previous list
  and logs the failure.
- apply()'s empty-exe-name refusal ran after target_ip had already
  been overwritten and the error path did not restore it; validation
  now runs before any state mutation (launch() already did), with a
  regression test.
- Watchdog commit could overwrite fresher UI bookkeeping: the plan
  now carries the snapshot's injected-PID map, and commit skips any
  entry whose live map changed during the injection window (logged
  as WATCHDOG_COMMIT_RACE_SKIPPED), with tests.
- When the adapter-loss policy deletion fails, commit no longer
  discards the cycle's real injections (which caused re-injection
  attempts into already-hooked processes every cycle); it records
  them and retries the deletion next cycle.
- Profile-apply retry is per-rule: previously one successful rule
  stopped all retries, leaving startup-failed rules dead while the
  profile looked active. Only rules with no entry or a Failed entry
  are retried; satisfied rules are not re-applied.
- The per-app status cache no longer rescans all processes per app
  or allocates a fresh lowercase string per (network PID × app):
  paths are lowercased once per refresh and indexed by path.
- The watchdog thread is supervised and its sampling is fail-soft:
  it publishes a heartbeat every cycle and the UI tick respawns it
  after 45 s without one (a panic in the cycle used to kill all
  enforcement silently), and a failed adapter enumeration now reuses
  the last good list instead of reading as "adapter lost" (two empty
  samples could trip the fail-close on a healthy adapter). Profile
  applies whose counts were discarded at four call sites now log
  their failures with the calling context.

UI honesty and interaction:
- Custom-app removal is now confirmed and fully wired: it stops the
  live bypass, removes the app's rules from every profile, lifts its
  firewall block, and reports what was cleaned. (Previously: one
  click, no confirmation, and all three were orphaned.)
- The confirmation dialog is a real modal (egui::Modal backdrop
  consumes background input; tray actions are not consumed while it
  is open) and has a keyboard contract: Enter confirms, Esc cancels.
- Success banners are built from the operations' actual results
  (profile switch/save/revert, rule remove/toggle, rename, duplicate):
  a partial or failed operation no longer gets an unconditional ✔.
  save_current_bypasses_to_active_profile also reports save failures
  it previously swallowed silently.
- Busy feedback: heavy row operations (toggle, block, launch) and
  Refresh run through a one-frame-deferred pattern — the click arms
  the operation, a "Working…" spinner frame is presented, then the
  operation executes. (The full async refactor remains deferred, see
  below; the window still blocks during execution itself.)
- Profile name uniqueness is enforced on rename and duplicate too
  (duplicates auto-suffix "(Copy 2)", …); a refused rename keeps the
  editor open with the attempted name. The rename field accepts
  Enter/Esc like the create field.
- The "BYPASS CONFIGURED" pill renders amber in both of its states
  (the not-in-live-map arm was slate gray — an undocumented third
  state). Helper-process widening gets a visible line under the row,
  not only hover text; every Failed row shows a reason line (generic
  fallback inline); selected app rows are outlined, not just marked
  with a glyph; the stats row and the Apps toolbar wrap instead of
  clipping at the minimum window width; empty states distinguish
  "catalog empty" from "no filter match", and the Network tab has an
  empty state; orphaned blocked entries are labelled "Unknown app
  (leftover entry)" instead of a bare UUID; tray menu items enable/
  disable with engine state; autostart strings say "logon", not
  "boot"; "Save Preferences" is now "Save All Settings", and the
  Modified indicator explains itself on hover.

Security:
- The autostart protected-location gate now also reads the object's
  OWNER: an untrusted owner implicitly holds WRITE_DAC, so a
  user-owned folder with a hand-crafted clean DACL no longer passes.
- Hook-status reports in %TEMP% are ignored while the protected
  ProgramData status directory exists (a planted "OK 5" there could
  fake a Live status).
- set_autostart re-proves the ProgramData folder ACL before writing
  the task XML, like policy publishing does.
- ACL verification no longer demands OI|CI inheritance flags on leaf
  files (directories still require them): the flags are meaningless
  on files and Windows may normalize them, which would have failed
  every verification (this was an INFERENCE risk in the audit).
- The hook's policy fingerprint now includes a content hash, so a
  same-size policy rewrite inside one FILETIME tick (e.g. a swapped
  target IP) is detected; ProgramData/TEMP path lengths from the
  environment APIs are bound-checked before use.
- block_app's verification-failure path now attempts the same
  verified cleanup as the partial-success path instead of leaving
  possibly-created rules behind a "failed" report.
- The hook DLL is built with Control Flow Guard (/guard:cf +
  /GUARD:CF) explicitly.
- CI: third-party actions are pinned to API-verified commit SHAs
  (dtolnay/rust-toolchain excepted — its ref selects the toolchain),
  and a non-blocking cargo-audit job runs on every push.
- Vendored MinHook is now documented in cpp/minhook/VENDORED.md, and
  docs/ARCHITECTURE.md's stale "two locations" allow-list claim is
  corrected (policy lives only in %ProgramData%\BiFlow).

Still deferred (unchanged honesty notes):
- Moving blocking engine work fully off the UI thread (the busy
  pattern above mitigates feedback, not the block itself) and the
  manager-mutex hold during UI-initiated injection — one
  architectural item, to be validated on a real Windows device.
- Trust roots still read ProgramData/ProgramFiles from the process
  environment (fail-closed in the common cases); switching to
  SHGetKnownFolderPath is planned with the same device validation.
- Whole-card click-to-select and text-size/target enlargements wait
  for the screenshot QA pass listed in the audit's release checklist.

## v0.3.3 — 2026-11-03

Fix wave from the internal granular four-layer audit of v0.3.2
(~48 findings; report only at the time). Every actionable finding is
addressed below. One audit claim did not survive re-verification and is
listed as such; the one remaining architectural item is declared
openly at the end.

Security:
- Hook DLL: hook installation is now all-or-nothing — a partial hook
  set is torn down (MH_Uninitialize) and reported as an error instead
  of being enabled while the injector reported the injection failed.
  Hook fallbacks never call the imported ws2_32 exports from inside
  the DLL (defense-in-depth against re-entering a patched export);
  a missing trampoline fails that one call. (Audit 🔴: on re-reading,
  the claimed self-recursion crash was NOT reachable — an installed
  hook always has its trampoline, and the direct-export fallback ran
  only when the target export was not patched. The hardening above
  removes the fragile pattern regardless.)
- Autostart: the protected-location gate now verifies the executable
  directory's actual DACL (no write-like rights for Users / Everyone /
  Authenticated Users / CREATOR OWNER / the current user) on the
  canonicalized path — a user-created subfolder of %ProgramData%
  previously passed the prefix test. The task XML principal is the
  current user's SID from the process token (never environment
  variables, never silently omitted). Disabling autostart now verifies
  BOTH the task and the Run key with a strict (tri-state) query.
- ACL application now verifies the DACL read-back too (exact ACE set),
  not only the owner. Policy-file temp names are unique per publish
  (UI and watchdog threads could share a pid-only temp name), and a
  failed pre-rename flush fails the publish.
- Config: a corrupt config now takes the same protective path as an
  unreadable one (preserved as a collision-safe `.corrupt` copy,
  saving disabled, warning shown) instead of a silent reset with
  saving enabled. `schema_version` is enforced (newer = refuse).
  Nested config types carry serde defaults, so one malformed entry no
  longer destroys the whole file. Load-time sanitizing merges
  duplicate rules and drops rules/custom apps without absolute exe
  paths. Removed the dead `Profile.priority` and `AppEntry.valid`
  fields (old configs still load).
- Firewall: netsh is invoked with argv arrays (the format-string +
  re-tokenize layer is gone); PowerShell query helpers escape their
  substitutions internally; a partial block's rollback removal is
  verified before the error message may claim it; clear-all verifies
  from one batch readback (was 2N+2 PowerShell spawns); startup
  reconcile is one batch query; terminated-connection counts are
  logged.
- Shell token duplication uses least-privilege rights instead of
  TOKEN_ALL_ACCESS; re-elevation forwards the original arguments
  (e.g. `--minimized`).

Reliability / logic:
- Policy files publish allow-list first, then the target IP.
  `apply`/`launch` refuse an empty exe name before mutating state.
  Adapter-loss fail-close keeps truthful bookkeeping and retries when
  the policy deletion fails (the failure is logged, not discarded).
  Manual operations reset the adapter-missing counter. Partial
  per-PID injection failures, profile-apply failures and skipped
  rules are logged. Several previously discarded engine results
  (profile switch/create/revert, adapter change, block pre-removal,
  rule removal) are now surfaced in the status. Network-PID
  enumeration distinguishes failure (None) from empty; adapter
  enumeration retries buffer overflows. Discovery failures are logged;
  the file picker re-validates .exe; pathless running entries are
  dropped. Exit persists session preferences first.

Performance:
- The UI tick no longer enumerates processes, four connection tables
  and adapters on the UI thread: the watchdog thread publishes its
  snapshot and the tick consumes it. The process-path buffer is
  thread-local (was a 64 KiB allocation per PID per pass); the
  discarded basename process map is no longer built; watchdog
  planning lowercases paths once per cycle. Elevation checks are
  cached; the System32 lookup uses a stack buffer.

UI/UX:
- Action notifications are global (every tab), colored by outcome
  (errors no longer render green), and survive tab switches.
  The status bar colors failures red. Confirmation dialogs guard
  profile deletion, rule removal, Unblock All, and choosing a VPN
  adapter as Direct. Custom apps can be removed. Failed bypasses show
  their reason under the row; the Live pill's hover lists helper
  processes being bypassed and any policy-sync problem. The
  "BYPASS CONFIGURED" pill is amber. Adapter cards for down /
  APIPA / no-IPv4 adapters are not selectable, with the reason shown;
  VPN cards carry a warning. Honest wording throughout ("Open
  Connections", the firewall block description, the About claims).
  Blocked apps are listed and manageable in Settings; profile rules
  show and toggle their enabled state; per-app version/source are
  shown; empty list state, Ctrl+F search focus, Unicode search,
  Enter-to-create profile, duplicate-name and empty-rename guards.
  The tray gained a Resume action and a live-state tooltip; a refused
  tray Exit re-shows the window with the reason.

Deliberately deferred (declared, not silently dropped): moving the
blocking toggle/launch/block operations themselves off the UI thread
is an architectural change to the apply flows; it is postponed until
it can be validated on a real Windows device, rather than shipped
unverifiable. Runtime behaviour on real Windows remains the open
verification item, as with previous releases.

## v0.3.2 — 2026-11-01

Third external review (14 findings: 4 P1 + 8 P2 + 2 P3, of v0.3.1 @
8506813) verified line-by-line against the source; every finding was
confirmed in code (BF-12 additionally against crates.io metadata) and is
fixed below. Runtime behaviour on real Windows remains the open
verification item, as with previous releases.

### Hook status reporting (BF-01)
- The hook's status report could never be written: it lived in the
  policy folder, whose ACL gives standard users read/execute only, while
  the hook runs inside target processes at the user's normal integrity —
  so injections timed out and "Launch Direct" terminated the launched
  process. Status reports now live in a dedicated `status` subfolder
  whose ACL grants users write access, the hook falls back to
  `%TEMP%\BiFlow` when the report cannot be written there, and BiFlow
  deletes any stale report for a PID before injecting.

### Elevated trust boundary (BF-02, BF-03)
- System tools (`netsh`, `schtasks`, `powershell`) are now launched by
  absolute System32 path (resolved via `GetSystemDirectoryW`), never by
  bare name: CreateProcessW searches the executable's own folder before
  System32, so a planted same-named binary next to a portable BiFlow
  would have run with BiFlow's administrator token.
- The ProgramData ACL application now also sets and verifies the owner
  (Administrators): an object's owner implicitly holds WRITE_DAC, so the
  previous DACL-only protection let the folder's creator rewrite the
  ACL. The protected ACL is now applied (checked) to the root folder on
  the DLL-extraction and policy-publish paths, and to the autostart
  task XML; the XML's `%TEMP%` fallback location is removed.

### Autostart task (BF-04)
- Registering the logon task is refused when BiFlow runs from a
  user-writable location: the task executes `current_exe` with
  HighestAvailable, so a replaceable portable binary would have been an
  elevation/persistence vector (LIMITATIONS.md #19).
- Disabling autostart now verifies the task is actually gone (the
  `schtasks /Delete` result was ignored), and the settings UI reports
  the real result instead of an unconditional success.

### Enforcement correctness (BF-05..BF-10)
- Helper/descendant processes the watchdog injects are now published on
  the policy allow-list with the app's own path: previously they were
  hooked (and shown Live) but their own path was not listed, so the
  hook never bypassed them. The list republishes when the effective
  set changes.
- Profile rules that could not be applied at startup (no usable
  adapter yet) are retried automatically when an adapter appears
  (throttled), instead of staying inert until a manual toggle.
- An APIPA (link-local) address is no longer accepted as a usable
  direct IPv4 — not at apply/launch time and not in the watchdog, where
  it now counts as "adapter unavailable" (fail-closed path).
- A saved adapter GUID that no longer matches anything no longer falls
  back to the saved IfIndex (indices are recycled and can name a
  different adapter); auto-detection is used instead.
- The watchdog re-resolves the adapter address immediately before
  committing, so a mid-cycle adapter switch can no longer publish the
  previous adapter's IP.
- Exit (button, tray, window close) no longer ignores policy-cleanup
  failures: if the policy files cannot be deleted, the app stays
  running and reports it, instead of exiting while already-injected
  processes keep bypassing.

### Firewall verification (BF-11)
- Rule readback is structured (PowerShell firewall objects) instead of
  name-substring matching in netsh text: a block counts only when the
  rule is enabled, blocks, and targets exactly the app's executable —
  per direction. This also removes the dependency on netsh's localized
  "No rules match" sentence.
- The "Unblock All" purge is a checked operation and afterwards ALL
  remaining `BiFlow_Block*` rules are enumerated, so orphans can no
  longer survive a reported success; the settings UI follows the real
  result. Wording that claimed "complete/instant" blocking was
  corrected.

### Build & docs (BF-12, BF-13, BF-14)
- Declared MSRV corrected from 1.74 to 1.90 (the locked `tray-icon`
  0.26.0 requires 1.90 and `eframe`/`egui` 0.33.3 require 1.88), with a
  CI job that checks the build on the declared toolchain.
- "Active Internet" wording corrected to what is measured: established
  TCP connections / UDP endpoints (a socket snapshot, not traffic).
- SECURITY.md no longer describes the removed `%TEMP%` policy copies;
  the About tab says Task Scheduler (not "registry auto-run"); the
  README logo points at the existing `assets/icon_256.png`;
  LIMITATIONS.md numbering is sequential again (the v0.3.1 items
  formerly numbered 15–18 are now 11–14).

## v0.3.1 — 2026-10-25

Second external review (16 findings: 7 P1 + 10 P2, of v0.3.0) verified
line-by-line; every finding was confirmed in code and is fixed below,
except P1-6, which is documented as an inherent Winsock-hook limitation
(see LIMITATIONS.md). CI quality gates are now blocking.

### Firewall (P1-1, P1-2)
- Block verification now checks the inbound and outbound rule separately
  (netsh readback per direction): an existing rule in one direction can no
  longer mask a missing rule in the other. A failed query is "unknown",
  never "absent". Partial creation rolls the surviving half-rule back.
- Unblock and batch-clear verify removal per direction and per app, and
  report every ID that could not be removed or verified; the UI only
  drops apps whose removal was actually verified. The PowerShell fallback
  now creates rules with the same `-Name` netsh uses, so the readback can
  see them.

### Policy publication (P1-3, P2-10)
- Policy writes are no longer silently ignored: `update_target_ip`,
  `update_bypass_app_list` and `clear_target_ip` return `Result`, policy
  files are written via temp-file + flush + rename-replace, and every
  manager operation (apply, launch, remove, clear, watchdog drift) rolls
  its in-memory change back when publication fails instead of claiming a
  bypass that was never published.
- `%TEMP%` policy fallbacks are removed entirely (Rust writer and C hook):
  `%ProgramData%\BiFlow` is the only policy location, and a missing
  allow-list is now fail-closed (bypass off), not permissive. Legacy TEMP
  copies are still deleted on cleanup.

### Live semantics and watchdog (P1-4, P2-5)
- If the direct adapter reports no usable IPv4 for two consecutive
  watchdog cycles, the policy is fail-closed (files deleted, entries
  marked Failed) instead of leaving injected processes bound to a stale
  address while the UI reports Live.
- The watchdog cycle is split into snapshot / plan + inject / commit, so
  the manager mutex is never held across an injection wait; the UI renders
  from one status snapshot per frame instead of three locks per row.

### Profiles and pause (P1-5, P2-1, P2-3, P2-7, P2-6, P2-8)
- Profile rules now register in the enforcement manager even when the app
  was never discovered (by stored exe_path), so the watchdog injects the
  process when it later appears; startup no longer silently drops them.
- Pause is recomputed from "enabled rules not currently enforced" after
  every change: enabling one app while paused can no longer hide Resume
  for the others.
- `Profile.enabled=false` is now honored by automatic application
  (startup, adapter switch); explicit actions (toggle, launch, resume,
  switch-to) wake a dormant profile.
- Profiles created from an auto-detected adapter now resolve and store
  the adapter GUID, not just the unstable IfIndex (also fixed in
  save-current-bypasses and at startup).
- Toggle/remove/save now sync the profile baseline only when the save
  succeeds, so "Modified" can never describe an already-persisted change
  and Revert can never undo one; `save()` returns `Result` and every
  caller reports a persistence failure instead of overwriting it with a
  success message.

### Status correctness (P2-2, P2-4)
- "Running" and "Active Internet" are decided by full executable path
  only; the basename-keyed process map is no longer consulted, so a
  same-name binary in another folder cannot make an app look running or
  online. Auto-discovery dedups by exe path only (no display-name match).
- Launch status no longer says "directly bypassing VPN": it reports the
  hook installation and states that the egress route is not verified; the
  Live pill hover says the same.

### Hook (P2-9, P1-6)
- connect/WSAConnect/sendto/WSASendTo now require a complete `sockaddr_in`
  (`namelen >= sizeof(sockaddr_in)`) before casting, closing the
  short-sockaddr over-read (bind already checked).
- P1-6 documented, not "fixed": at bind time a future `listen()` cannot
  be distinguished from a ConnectEx client bind, and a bound socket cannot
  be unbound, so an INADDR_ANY:0 TCP listener of a bypassed app listens
  on the physical IP only. Servers binding an explicit port are unaffected.

### ACL (P1-7)
- The ProgramData DACL now carries OI/CI inheritance, is applied with
  `SetNamedSecurityInfoW` (not the superseded `SetFileSecurityW`), and is
  verified: bin/, the DLL file and every policy file get the checked ACL,
  and a failure fails the extraction/publication instead of proceeding on
  assumed protection.

### Quality gates
- `cargo fmt --check` passes (whole tree formatted) and
  `cargo clippy --locked --all-targets -- -D warnings` passes on the
  Windows target; both CI steps are now blocking instead of
  `continue-on-error`.

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
