# Agent fleet packaging (MDM / GPO residual)

Silent multi-endpoint deploy for `bsdm-agent` (**agent-spike**). This is the
**Phase C residual** beyond pilot installers: Intune / GPO / Jamf-oriented
artifacts and silent install flags.

| In scope | Out of scope (customer pipeline) |
|---|---|
| Silent installers (`--silent` / `-Silent`) | Apple Developer ID + **notarization** |
| Intune Win32 wrap scripts + detection | Authenticode / EV code signing |
| GPO ADMX registry keys | Microsoft Store / winget publication |
| macOS `pkgbuild` unsigned payload | Full MDM product UI |
| Configuration Profile example | Production IdP binding |

**Honesty:** packages produced here are **unsigned**. Sign and notarize in your
enterprise pipeline before production fleet rollout.

## Layout

```
fleet/
  windows/
    intune/     # detection, uninstall, Win32 package notes
    gpo/        # ADMX/ADML for Control Plane URL + tokens path
  macos/
    build-pkg.sh
    com.bsdm.agent.mobileconfig.example
  linux/
    install-silent.sh
```

## One-shot silent examples

### Linux (Ansible / Salt / MDM script)

```bash
sudo ./packaging/agent/install-linux.sh --silent \
  --bin ./dist/bsdm-agent-linux-amd64 \
  --control-plane-url https://control.corp:9090 \
  --control-token "$CONTROL_API_TOKEN" \
  --enroll-token "$AGENT_ENROLL_TOKEN" \
  --device-id "$(hostname -s)" \
  --enable --set-system-proxy
```

Or: `./packaging/agent/fleet/linux/install-silent.sh` (wrapper).

### macOS (Jamf policy script)

```bash
sudo ./packaging/agent/install-macos.sh --silent \
  --bin ./dist/bsdm-agent-darwin-arm64 \
  --control-plane-url https://control.corp:9090 \
  --control-token "$CONTROL_API_TOKEN" \
  --enroll-token "$AGENT_ENROLL_TOKEN" \
  --device-id "$(scutil --get LocalHostName)" \
  --set-system-proxy
```

Unsigned pkg (sign later):

```bash
./packaging/agent/fleet/macos/build-pkg.sh \
  --bin ./target/release/agent-spike \
  --out ./dist/bsdm-agent.pkg
# Then: productsign / notarytool in your CI
```

### Windows (Intune Win32 / GPO startup)

```powershell
.\packaging\agent\install-windows.ps1 -Silent `
  -BinSrc .\dist\bsdm-agent.exe `
  -ControlPlaneUrl "https://control.corp:9090" `
  -ControlToken $env:CONTROL_API_TOKEN `
  -EnrollToken $env:AGENT_ENROLL_TOKEN `
  -DeviceId $env:COMPUTERNAME `
  -SetSystemProxy
```

See [intune/](windows/intune/) for detection + uninstall scripts used with the
Microsoft Win32 Content Prep Tool.

## Build binaries for fleet drop

```bash
./scripts/build-agent-binaries.sh
# optional assembly:
./scripts/build-agent-fleet-packages.sh
```

## Docs

- Pilot agent lab: [pilot-agent.md](../../../docs/getting-started/pilot-agent.md)
- Fleet rollout guide: [pilot-agent-fleet.md](../../../docs/getting-started/pilot-agent-fleet.md)
