# Target setup artifacts (generated, review before installing)

Probe version **1.4.0**. Regenerate with `uv run atlas targets render`.
Do not edit these files: the collector pins the probe's SHA-256 and `atlas doctor`
reports any mismatch. Step-by-step instructions:
[docs/SETUP-TARGETS.md](../SETUP-TARGETS.md).

| File | Install as | Owner / mode |
|---|---|---|
| `atlas-probe` | `/usr/local/libexec/atlas-probe` | root:root 0755 |
| `atlas-probe-gate` | `/usr/local/libexec/atlas-probe-gate` | root:root 0755 |
| `sudoers.atlas-ro` | `/etc/sudoers.d/atlas-ro` | root:root 0440 (visudo -cf) |
| `authorized_keys.example` | `~atlas-ro/.ssh/authorized_keys` | atlas-ro 0600, dir 0700, owned by root is fine |

User: `atlas-ro`, a system account with no password (`passwd -l`), no docker group, no other sudo rights.
Implemented sections: `cron`, `docker`, `net`, `os`, `packages`, `pi`, `ports`, `procs`, `pve`, `services`, `storage`, `users`, `version`. `pi` needs Raspberry Pi OS (vcgencmd).

Debian/Ubuntu only (systemd ≥ 246, iproute2, util-linux, dpkg).

## SHA-256

```
95e3577dcb2283574a354e92217d97699560b0bb334c58336701413500f6df15  atlas-probe
fcc555e679baba6d3078061c703258919752aee048319ed6c116f72f6108343d  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
328d349b9d65ef79d37d9bfbbc57490d1f436f41c121888aed5cb7e785dfa157  sudoers.atlas-ro
```
