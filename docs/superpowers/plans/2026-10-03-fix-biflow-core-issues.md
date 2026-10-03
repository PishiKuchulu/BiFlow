# BiFlow Core Bug Fixes and Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the critical IP/pipe parsing bug in the MinHook DLL and injector, support ConnectEx via bind hook, enable automated recompilation in build.rs, implement elevated Windows Task Scheduler autostart, and update project documentation.

**Architecture:** 
1. C hook DLL (`cpp/biflow_hook.c`): Robust string parsing (strip trailing `|if_index`, newlines), fallback to `%ProgramData%\BiFlow\target_ip.txt`, and intercept `bind()` for ephemeral client ports (`sin_port == 0`) to support `ConnectEx` as well as `connect`/`WSAConnect`/`sendto`.
2. Build script (`build.rs`): Compare modification times of `cpp/biflow_hook.c` and `cpp/biflow_hook64.dll` so changes automatically trigger recompilation via MSVC `cl.exe`.
3. Autostart (`src/windows/autostart.rs`): Implement Windows Task Scheduler (`schtasks.exe`) with `/RL HIGHEST` to overcome UAC startup blocking on elevated executables.
4. Architecture docs (`docs/ARCHITECTURE.md`): Update to reflect the actual Winsock hook architecture.

**Tech Stack:** Rust 2021, C/C++17 (MSVC), Win32 API, MinHook, Windows Task Scheduler (`schtasks`), Windows Sockets 2 (`ws2_32`).

---

### Task 1: Fix Target IP Parsing and Hooking in `cpp/biflow_hook.c` and `src/windows/injector.rs`

**Files:**
- Modify: `cpp/biflow_hook.c`
- Modify: `src/windows/injector.rs`

- [ ] **Step 1: Enhance `load_target_ip` in `cpp/biflow_hook.c`**
  - Implement delimiter stripping: if `buf` contains `|`, `\r`, `\n`, or spaces, terminate string at delimiter.
  - Add search order:
    1. Environment variable `BIFLOW_TARGET_IP`
    2. `%TEMP%\biflow_target_ip.txt`
    3. `%ProgramData%\BiFlow\target_ip.txt`
  - Implement `Hook_bind`: If `sin_family == AF_INET && sin_port == 0 && sin_addr.s_addr == INADDR_ANY`, bind socket to `g_target_ip` before calling original `bind()`.

- [ ] **Step 2: Clean up IP writing in `src/windows/injector.rs`**
  - Ensure `update_target_ip` and `launch_with_bypass` format IP cleanly.
  - Maintain backward compatibility so both `ip` alone and `ip|if_index` parse correctly.

---

### Task 2: Fix Build Automation for Hook DLL in `build.rs`

**Files:**
- Modify: `build.rs`

- [ ] **Step 1: Update `build.rs` compilation trigger**
  - Instead of `if !dll_path.exists()`, check if `!dll_path.exists()` OR if `cpp/biflow_hook.c` has a newer modification time than `cpp/biflow_hook64.dll`.
  - Add `/utf-8` and standard C flags if needed.
- [ ] **Step 2: Recompile `cpp/biflow_hook64.dll` using MSVC `cl.exe`**
  - Execute compiler command to generate updated `cpp/biflow_hook64.dll`.
  - Verify new DLL exists and contains the updated symbol handlers.

---

### Task 3: Implement Elevated Autostart via Windows Task Scheduler in `src/windows/autostart.rs`

**Files:**
- Modify: `src/windows/autostart.rs`

- [ ] **Step 1: Update `is_autostart_enabled` and `set_autostart`**
  - In `is_autostart_enabled()`:
    - Query `schtasks /Query /TN BiFlow` (hidden window). If exit code is 0, return true.
    - Fallback: check `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
  - In `set_autostart(enable: bool)`:
    - If `enable == true`:
      - If elevated, run `schtasks /Create /TN "BiFlow" /TR "\"<exe>\"" /SC ONLOGON /RL HIGHEST /F`
      - Also register in registry `Run` as secondary fallback.
    - If `enable == false`:
      - Run `schtasks /Delete /TN "BiFlow" /F`
      - Delete value from registry `Run`.

---

### Task 4: Synchronize Documentation in `docs/ARCHITECTURE.md`

**Files:**
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Update architecture description**
  - Replace obsolete `FwpmConnectionPolicyAdd0` references with the active Winsock MinHook DLL injection architecture.
  - Document the socket binding mechanism, target IP resolution, and firewall isolation features.

---

### Task 5: Build, Test and Verify Entire Project

**Files:**
- Verify: `tests/unit_tests.rs`
- Run: `scripts/build-release.ps1`

- [ ] **Step 1: Run unit tests**
  - Execute `cargo test`.
- [ ] **Step 2: Build release binary**
  - Execute `scripts/build-release.ps1`.
  - Confirm `BiFlow.exe` is successfully compiled with all fixes embedded.
