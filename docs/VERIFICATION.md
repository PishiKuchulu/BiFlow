# Verification Policy

The application intentionally avoids fake verification.

A bypass is reported as `Live` in the UI only when (a) the hook DLL is present in the target process's module list and (b) the DLL itself reported back that all 5 of its Winsock hooks were installed successfully. A successful `LoadLibraryW` alone is never presented as a live bypass. The UI does not label the target `Verified Direct` because determining the observed path of arbitrary third-party traffic requires runtime evidence from the actual Windows host and the active VPN.

`Live` is a point-in-time proof of hook installation, not of policy or egress: the status is not re-validated per socket, and a stale policy is fail-closed, not hidden — if the direct adapter loses its IPv4, the watchdog deletes the policy files and marks entries Failed after two cycles. Firewall block/unblock results are likewise only reported after a per-direction netsh readback; a failed readback is reported as an error, never as success. Policy publication failures (apply, launch, remove, clear) roll the in-memory change back and are reported, so the UI never claims a bypass whose policy was not written.

For manual verification, compare:

- selected app's local interface/path
- a separate control application's path
- public IP observed by each
- behavior before/after enabling the policy

A kill-switch or provider-specific enforcement policy can still defeat direct egress.
