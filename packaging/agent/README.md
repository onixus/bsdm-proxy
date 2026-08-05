# BSDM Local Policy Agent — multi-OS pilot + fleet install

Lab/pilot packaging for `agent-spike` (`bsdm-agent` binary name on install).

Install scripts + system-proxy hooks for Linux, macOS, and Windows.

**Fleet residual (MDM/GPO):** silent flags, Intune/GPO/Jamf scaffolding under
[`fleet/`](fleet/). Packages are **unsigned** — sign/notarize in your enterprise
pipeline. Guide: [pilot-agent-fleet.md](../../docs/getting-started/pilot-agent-fleet.md).

## Build binary

```bash
cargo build -p agent-spike --release --bin bsdm-agent
# → target/release/bsdm-agent  (alias: agent-spike)
```

Cross targets (optional):

```bash
./scripts/build-agent-binaries.sh
```

## Install

| OS | Command |
|---|---|
| Linux | `sudo ./packaging/agent/install-linux.sh` |
| macOS | `sudo ./packaging/agent/install-macos.sh` |
| Windows | elevated `.\packaging\agent\install-windows.ps1` |
| Fleet silent | `--silent` / `-Silent` + `--control-plane-url` (see [fleet/](fleet/)) |

Edit env after install:

- Linux: `/etc/bsdm-agent/agent.env`
- macOS: `/usr/local/etc/bsdm-agent/agent.env`
- Windows: `C:\Program Files\BSDM Agent\etc\agent.env`

## System proxy

Points OS HTTP(S) settings at the BSDM **data plane** (default `127.0.0.1:3128`):

```bash
bsdm-agent --set-system-proxy
bsdm-agent --clear-system-proxy
bsdm-agent --set-system-proxy --dry-run
```

Env: `SYSTEM_PROXY_HOST`, `SYSTEM_PROXY_PORT`, `SYSTEM_PROXY_BYPASS`,
`SYSTEM_PROXY_LINUX_MODE` (`user`|`system`|`all`).

Session mode (set on start, clear on Ctrl+C):

```bash
AGENT_MANAGE_SYSTEM_PROXY=1 bsdm-agent
```

| OS | Mechanism |
|---|---|
| macOS | `networksetup` web/secure web proxy |
| Linux | GNOME `gsettings` + `~/.config/bsdm-agent/proxy.env` (+ optional `/etc/profile.d`) |
| Windows | WinINET registry + best-effort `netsh winhttp` |

## Service units

- Linux systemd: `packaging/agent/systemd/bsdm-agent.service`
- macOS LaunchDaemon: `packaging/agent/launchd/com.bsdm.agent.plist`
- Windows: Scheduled Task `BSDM-Agent` at logon

Guide: [pilot-agent.md](../../docs/getting-started/pilot-agent.md).
