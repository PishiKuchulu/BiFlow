# Limitations

1. The core enforcement currently targets IPv4. It does not claim verified IPv6 bypass.
2. Existing TCP connections are not migrated when a policy is enabled; start a new connection or restart the application for deterministic testing.
3. UWP/MSIX package-level enforcement is not implemented.
4. Native split-tunnel integration for third-party VPN clients is not implemented.
5. DNS traffic may still be handled by Windows DNS Client and can follow a different path from an application's payload traffic.
6. VPN kill-switches or security products may intentionally block direct egress; the application does not disable those protections.
7. Process-family/child-process aggregation is not guaranteed.
8. Network-interface detection is best-effort and should be reviewed by the user before enabling a policy.
9. Runtime path verification is intentionally not inferred from successful WFP API calls.
