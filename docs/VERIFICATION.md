# Verification Policy

The application intentionally avoids fake verification.

A bypass is reported as `Live` in the UI only when (a) the hook DLL is present in the target process's module list and (b) the DLL itself reported back that all 5 of its Winsock hooks were installed successfully. A successful `LoadLibraryW` alone is never presented as a live bypass. The UI does not label the target `Verified Direct` because determining the observed path of arbitrary third-party traffic requires runtime evidence from the actual Windows host and the active VPN.

For manual verification, compare:

- selected app's local interface/path
- a separate control application's path
- public IP observed by each
- behavior before/after enabling the policy

A kill-switch or provider-specific enforcement policy can still defeat direct egress.
