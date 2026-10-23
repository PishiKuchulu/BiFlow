# Build

Requirements:

- Windows 10 or Windows 11 x64
- Rust stable MSVC toolchain (`x86_64-pc-windows-msvc`)
- Visual Studio 2022 Build Tools with Desktop C++ workload and Windows SDK
  (provides `cl.exe`/`link.exe`; the hook DLL is compiled from C source)

Build:

```powershell
cargo build --release
```

## Hook DLL

The Winsock hook (`cpp/biflow_hook.c`, MinHook vendored under `cpp/minhook/`)
is compiled by `build.rs` with MSVC `cl.exe` (static CRT, `/MT`) into
`OUT_DIR/biflow_hook64.dll`, which is then embedded into `BiFlow.exe` via
`include_bytes!` and extracted at runtime to
`%ProgramData%\BiFlow\bin\biflow_hook64_v<version>.dll` (content-verified
before injection). The DLL is **never committed** and never written into
the source tree — it is always built from source, so the binary always
matches the C source in the tree.

Release packaging:

```powershell
.\scripts\build-release.ps1   # builds + stages BiFlow.exe at repo root
.\scripts\package-portable.ps1 # builds + zips a portable directory
```
