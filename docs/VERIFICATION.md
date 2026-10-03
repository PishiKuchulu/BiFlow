# Verification Policy

The application intentionally avoids fake verification.

A policy is reported as `Applied` only after the Windows API accepts it. The UI does not label the target `Verified Direct` because determining the observed path of arbitrary third-party traffic requires runtime evidence from the actual Windows host and the active VPN.

For manual verification, compare:

- selected app's local interface/path
- a separate control application's path
- public IP observed by each
- behavior before/after enabling the policy

A kill-switch or provider-specific enforcement policy can still defeat direct egress.
