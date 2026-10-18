# Limitations

1. The core enforcement currently targets IPv4. It does not claim verified IPv6 bypass.
2. Existing TCP connections are not migrated when a policy is enabled; start a new connection or restart the application for deterministic testing. Disabling likewise affects only new sockets in already-injected processes.
3. Only sockets bound to `INADDR_ANY` are redirected. Sockets the application explicitly binds to a specific local address or port are left untouched.
4. UWP/MSIX package-level enforcement is not implemented.
5. Native split-tunnel integration for third-party VPN clients is not implemented.
6. DNS traffic may still be handled by Windows DNS Client and can follow a different path from an application's payload traffic.
7. VPN kill-switches or security products may intentionally block direct egress; the application does not disable those protections.
8. Process-family/child-process aggregation is not guaranteed.
9. Network-interface detection is best-effort and should be reviewed by the user before enabling a policy.
10. Chromium-based browsers launched via "Launch Direct" run with `--disable-features=RendererCodeIntegrity --no-proxy-server` (required for the hook to load); this weakens the browser sandbox's code-integrity check and ignores the system proxy for that instance.
11. 32-bit (WOW64) processes cannot be hooked (64-bit DLL); they are detected and skipped.
