# Networking Model

The project distinguishes three different concepts:

- Proxy bypass: removing or avoiding proxy settings.
- Route policy: selecting a source address/interface/gateway for outbound connections.
- VPN bypass: a verified application path that leaves the VPN tunnel.

PerAppBypass currently implements the middle layer for IPv4 process-based routing. The last statement (VPN bypass) must be verified against a real VPN/tunnel and is not inferred from configuration alone.
