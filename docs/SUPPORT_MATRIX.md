# Support Matrix

| Scenario | Detection | Enforcement | Verified here |
|---|---|---|---|
| Generic full-tunnel VPN (IPv4) | Best-effort heuristic | Winsock hook: bind to direct adapter IP | Runtime test required |
| WireGuard / OpenVPN / sing-box / Clash / v2ray / Tailscale | Heuristic adapter detection | Same Winsock hook path | Runtime test required |
| System proxy | Not the core path | Not implemented as global mutation | No |
| SOCKS/local proxy | Not the core path | Not implemented | No |
| UWP/MSIX | Partial discovery, not guaranteed | Not implemented | No |
| IPv6 | Interface discovery only | Not implemented | No |
| 32-bit (WOW64) processes | Discovered | Skipped (64-bit hook DLL) | By design |

"Verified here" means verified against a real VPN/tunnel on a Windows host —
see `docs/TESTING.md`. Configuration success alone is not a bypass test.
