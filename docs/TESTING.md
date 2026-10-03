# Testing

## Build

On Windows 10/11 x64 with the Rust MSVC toolchain and Visual Studio Build Tools installed:

```powershell
cargo fmt --check
cargo check
cargo test
cargo build --release
```

## Core acceptance test

1. Connect a real VPN/tunnel.
2. Confirm a control application uses the VPN public IP.
3. Run PerAppBypass elevated.
4. Select a physical/direct adapter with IPv4 and gateway.
5. Add/select a Win32 executable.
6. Enable Direct Bypass.
7. Make a new connection from that application.
8. Verify the selected application's path/interface and public IP independently.
9. Verify the control application still uses the VPN.
10. Disable the policy and repeat.

A successful `FwpmConnectionPolicyAdd0` call is not itself a bypass test.
