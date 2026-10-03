# Build

Requirements:

- Windows 10 or Windows 11 x64
- Rust stable MSVC toolchain
- Visual Studio 2022 Build Tools with Desktop C++ workload and Windows SDK

Build:

```powershell
cargo build --release
```

The build script compiles `cpp/wfp_bridge.cpp` and links against the Windows SDK libraries required for WFP/IP Helper.
