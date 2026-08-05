# Microsoft Intune (Win32) — BSDM Agent

## Package contents

Build a folder:

```
intune-drop/
  bsdm-agent.exe      # from scripts/build-agent-binaries.sh (windows)
  install.ps1
  detection.ps1
  uninstall.ps1
```

## Create .intunewin

```powershell
# Microsoft Win32 Content Prep Tool
IntuneWinAppUtil.exe -c .\intune-drop -s install.ps1 -o .\out
```

## App settings (Intune portal)

| Field | Value |
|---|---|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File install.ps1` |
| Uninstall command | `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1` |
| Detection | Use `detection.ps1` (custom script) or file existence of `C:\Program Files\BSDM Agent\bin\bsdm-agent.exe` |
| Device restart | No |
| Assignment | Required / pilot ring |

Pass control plane URL and tokens via **Intune script parameters** or
**Managed App Configuration** mapped into process env before install
(`CONTROL_PLANE_URL`, `CONTROL_API_TOKEN`, `AGENT_ENROLL_TOKEN`). Prefer
enroll-scoped tokens, not long-lived admin tokens.

## Signing

Sign `bsdm-agent.exe` with your Authenticode certificate **before** packaging.
Unsigned binaries may be blocked by WDAC / Smart App Control.
