# Security

- No telemetry.
- No DLL/code injection.
- No hidden persistence.
- No firewall or antivirus disabling.
- WFP state is created in a dynamic session owned by this process.
- Only PerAppBypass-created policy keys are removed by the app.
- Elevated mode is required for the advanced enforcement path on typical Windows installations.

The application changes outbound connection policy for selected applications. Users should only use it on machines they own or administer.
