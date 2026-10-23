# Third-Party Components

## MinHook

- **What:** The Minimalistic x86/x64 API Hooking Library for Windows
  (Tsuda Kageyu), vendored under `cpp/minhook/` (include + src only are
  compiled; the upstream Visual Studio project files are kept for
  reference).
- **Used for:** installing the Winsock hooks inside `biflow_hook64.dll`.
- **License:** BSD 2-Clause — see `cpp/minhook/LICENSE.txt` and
  `cpp/minhook/AUTHORS.txt`.

## Rust crates

BiFlow's Rust dependencies are listed in `Cargo.toml` / `Cargo.lock`
(notably `eframe`/`egui`, `windows-sys`, `winreg`, `rfd`, `tray-icon`,
`serde`, `uuid`). Each is distributed under its own license (MIT and/or
Apache-2.0 for the set used here).
