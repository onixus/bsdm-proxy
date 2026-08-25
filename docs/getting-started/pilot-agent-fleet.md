# Agent fleet packaging (MDM / GPO)

> **Lab-only (Beta).** The Local Policy Agent, `bsdm-connect` and the AmneziaWG
> path are **not part of the pilot production path and are not supported in
> production**. Maturity in [project-status.md](../project-status.md): **Beta
> (lab)**; the Day-1 pilot scope matrix marks them **OFF**
> ([pilot-deployment.md](pilot-deployment.md)). Run them on lab devices only —
> packages are unsigned/unnotarized and there are no availability or support
> guarantees for this path (issue #331).

Silent multi-endpoint distribution for the **Local Policy Agent** (`agent-spike` →
`bsdm-agent`). Complements [pilot-agent.md](pilot-agent.md) (lab smoke) with
**fleet residual** packaging from Phase C.

| Layer | Status |
|---|---|
| Pilot multi-OS installers + system proxy | Done (lab) |
| Silent install flags + fleet env write | Done |
| Intune Win32 scripts + detection | Scaffolding (unsigned) |
| GPO ADMX + registry → env | Scaffolding |
| macOS pkgbuild + Configuration Profile example | Scaffolding (unsigned) |
| Notarization / Authenticode / Store | **Customer pipeline** |

Artifacts live under [`packaging/agent/fleet/`](../../packaging/agent/fleet/).

---

## Security model (honest)

1. **Do not** embed long-lived `CONTROL_API_TOKEN` admin secrets in device images
   when an **enroll-scoped** token (`AGENT_ENROLL_TOKEN`) is available.
2. Prefer **file-backed** secrets delivered by MDM (encrypted profile / keychain /
   DPAPI path referenced by GPO) over plain registry values.
3. Packages from this repo are **unsigned**. Production requires:
   - Windows: Authenticode (EV optional for reputation)
   - macOS: Developer ID Installer + **notarytool** notarization
   - Linux: org-signed deb/rpm or verified binary hash via config management

---

## Build fleet drop

```bash
./scripts/build-agent-binaries.sh    # optional cross builds
./scripts/build-agent-fleet-packages.sh
# → dist/fleet/{linux,macos,windows}/ …
```

---

## Windows — Intune

1. Place `bsdm-agent.exe` + scripts from `packaging/agent/fleet/windows/intune/`.
2. Run **Win32 Content Prep Tool** → `.intunewin`.
3. Install: `powershell -ExecutionPolicy Bypass -File install.ps1`
4. Detection: `detection.ps1`
5. Uninstall: `uninstall.ps1`

See [intune README](../../packaging/agent/fleet/windows/intune/README.md).

### GPO

1. Copy ADMX/ADML to `PolicyDefinitions`.
2. Configure **BSDM → Local Policy Agent** (control plane URL, enroll token path).
3. Deploy binary via software install or Intune first.
4. Computer Startup: `apply-from-registry.ps1` maps HKLM policies → `agent.env`.

---

## macOS — Jamf / Apple MDM

### Package

```bash
./packaging/agent/fleet/macos/build-pkg.sh \
  --bin ./target/release/agent-spike \
  --out ./dist/bsdm-agent.pkg
```

Sign + notarize in CI (`productsign`, `notarytool`). Upload to Jamf as package.

### Settings profile

Example: `packaging/agent/fleet/macos/com.bsdm.agent.mobileconfig.example`.

Follow-up Jamf script (silent install + env):

```bash
sudo ./packaging/agent/install-macos.sh --silent \
  --bin /path/to/bsdm-agent \
  --control-plane-url "$4" \
  --enroll-token "$5" \
  --device-id "$(scutil --get LocalHostName)" \
  --set-system-proxy
```

(Jamf script parameters `$4`… are conventional for policy scripts.)

---

## Linux — fleet

```bash
export CONTROL_PLANE_URL=https://control.corp:9090
export CONTROL_API_TOKEN=…   # or enroll-only token
export AGENT_ENROLL_TOKEN=…
export DEVICE_ID=$(hostname -s)
export BSDM_AGENT_BIN=/path/to/bsdm-agent
export SET_SYSTEM_PROXY=1
sudo ./packaging/agent/fleet/linux/install-silent.sh
```

Or Ansible `command:` / Salt `cmd.run` invoking `install-linux.sh --silent … --enable`.

---

## Acceptance (fleet residual)

- [ ] Silent installers accept control-plane URL + tokens without interactive edit
- [ ] Intune detection returns installed only when binary + `CONTROL_PLANE_URL` present
- [ ] GPO ADMX loads in gpedit / domain Central Store
- [ ] macOS pkg installs binary + LaunchDaemon path (unsigned ok in lab)
- [ ] Documented signing/notarization handoff for production
- [ ] Lab enroll still works via [run-agent-pilot-smoke.sh](../../scripts/run-agent-pilot-smoke.sh)

---

## Related

- [agent-contract.md](../architecture/agent-contract.md)
- [ADR 0005](../adr/0005-local-policy-agent-vs-tunnel-first.md)
- [packaging/agent/README.md](../../packaging/agent/README.md)
