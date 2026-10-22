# Ask Claude about your homelab (MCP)

atlas includes an [MCP](https://modelcontextprotocol.io) server. Connect it to Claude Code or
Claude Desktop and ask in plain words:

- *"What is running on docker01?"*
- *"Which VMs are on pve2, and which are stopped?"*
- *"Is Pi-hole running anywhere? On which IP?"*
- *"What changed on the NAS this week?"*
- *"Which services failed?"* · *"Who has 10.0.20.31?"* · *"Why is jellyfin not documented?"*
- *"Check docker01 now and tell me what's running."* (with live scans enabled, see below)

Claude answers from atlas's inventory, and every answer says when the data was collected.
atlas stays read-only towards your machines. The only thing Claude can trigger (if you allow it)
is a fresh read-only scan of one machine.

## Option A: over SSH (recommended)

Claude starts `atlas mcp` on the atlas VM through SSH. No port to open, no token, no TLS
certificate: your SSH login is the authentication.

**1. On the atlas VM, once:**

```bash
sudo atlas mcp-allow youruser
```

This lets `youruser` run exactly `sudo atlas mcp` without a password prompt (one line in
`/etc/sudoers.d/atlas-mcp`, checked by `visudo`). Add `--allow-scan` to also let Claude ask for
fresh scans:

```bash
sudo atlas mcp-allow youruser --allow-scan
```

**2. On your PC:** SSH must log in **without a password prompt**, because Claude can't type one.
If `ssh youruser@atlas-vm` asks for a password, set up a key once:

```bash
ssh-keygen -t ed25519
```

```bash
ssh-copy-id youruser@atlas-vm
```

On Windows without `ssh-copy-id`, append the contents of `%USERPROFILE%\.ssh\id_ed25519.pub`
to `~/.ssh/authorized_keys` on the VM. Then check that this starts without asking for anything
and waits silently. That silence is the server waiting for Claude; press Ctrl+C to quit:

```bash
ssh -T youruser@atlas-vm sudo atlas mcp
```

**3a. Claude Code:**

```bash
claude mcp add --transport stdio --scope user atlas -- ssh -T youruser@atlas-vm sudo atlas mcp
```

With live scans, end the command with `sudo atlas mcp --allow-scan` instead. `--scope user` makes
atlas available in every project. Check it with `claude mcp list` (it should say *Connected*), or
`/mcp` inside a session.

**3b. Claude Desktop:** Settings → Developer → *Edit Config* opens `claude_desktop_config.json`:
`%APPDATA%\Claude\` on Windows, `~/Library/Application Support/Claude/` on macOS. Add:

```json
{
  "mcpServers": {
    "atlas": {
      "command": "ssh",
      "args": ["-T", "youruser@atlas-vm", "sudo", "atlas", "mcp"]
    }
  }
}
```

Add `"--allow-scan"` at the end of `args` for live scans. On Windows, if Claude can't find
`ssh`, use the full path: `"command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe"`. Quit Claude
Desktop completely (tray icon → Quit) and start it again. Logs are in
`%APPDATA%\Claude\logs\mcp-server-atlas.log` (macOS: `~/Library/Logs/Claude/`).

## Option B: HTTP with a token

The compose file has an optional read-only MCP service on port 8765 behind a bearer token
(`/opt/atlas/secrets/mcp_token`):

```bash
docker compose --project-directory /opt/atlas --profile mcp up -d
```

By default it listens on 127.0.0.1 only. To reach it from your PC, set `ATLAS_MCP_BIND` and
`ATLAS_MCP_HOST` in `/opt/atlas/.env` (see [DEPLOY.md](DEPLOY.md) §6). The traffic is plain HTTP,
so keep it on a trusted LAN or VPN. **Claude Code:**

```bash
claude mcp add --transport http --scope user atlas http://atlas-vm:8765/mcp --header "Authorization: Bearer <token>"
```

Claude Desktop's config file only starts local programs. To use HTTP from Desktop you need a
bridge such as the third-party [`mcp-remote`](https://github.com/geelen/mcp-remote), which needs
Node.js. Option A is simpler. This HTTP service is always read-only: it has no access to the
scan credentials, so `--allow-scan` is only available in Option A.

**Not supported: claude.ai "custom connectors".** They connect from Anthropic's cloud, so the
server would have to be reachable from the internet. Don't expose atlas to the internet: it holds
a map of your network.

## Tools

| Tool | Answers |
|---|---|
| `list_machines` | Every node, VM, LXC, host and NAS: IP, OS, size, apps, last scan |
| `whats_running` | One machine: apps, running and failed services, containers, ports, top processes, timers |
| `list_services` | Every systemd unit and container across machines, filtered by machine, state or type |
| `proxmox_overview` | Nodes with their guests (state, vmid, cores, memory, IP, bridge), plus totals |
| `what_changed` | Change events over the last N hours, optionally for one machine (and its containers) |
| `scan_status` | Each target's latest scan result, with the reason when it failed |
| `search_ip` | Who has an IP, or what is in a subnet. MACs too |
| `find_service` | A port, process, unit, container or image, anywhere |
| `get_host` | Everything atlas knows about one entity (raw facts) |
| `list_containers`, `list_hosts`, `list_unknown_devices`, `unrecognised_ports` | What their names say |
| `scan_machine` | **Only with `--allow-scan`.** Rescans one machine now (read-only), at most once a minute per machine |

## Privacy

What Claude reads becomes part of your conversation, which is sent to Anthropic to generate the
answer. Secrets are already removed at collection time: env values, tokens, passwords and keys
never reach atlas's database. To also hide names, IPs and MACs, add `--sanitize`:
`sudo atlas mcp --sanitize` (also allowed by `mcp-allow`). Answers then use stable pseudonyms.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `claude mcp list` says *Failed to connect* | Run the same `ssh -T … sudo atlas mcp` in a terminal. A password prompt means step 2 (SSH key) or step 1 (`mcp-allow`) is missing. |
| `sudo: a terminal is required` | `mcp-allow` was not run for this user, or the command differs from `sudo atlas mcp` (it must match the rule exactly). |
| `atlas is not running` | `sudo atlas start` on the VM. |
| Claude says data is old | Enable `--allow-scan` and ask it to check now, or press *Scan* on the Targets page. |
| A machine is "not documented" | It is not an SSH target yet: add it on the Targets page. |
