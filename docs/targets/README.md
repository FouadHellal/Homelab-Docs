# Target setup artifacts (generated, review before installing)

Probe version **1.2.0**. Regenerate with `uv run atlas targets render`.
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
Implemented sections: `cron`, `docker`, `net`, `os`, `packages`, `pi`, `ports`, `services`, `storage`, `users`, `version`. `pi` needs Raspberry Pi OS (vcgencmd).

Debian/Ubuntu only (systemd ≥ 246, iproute2, util-linux, dpkg).

## SHA-256

```
e278b9344c49971a13e975a066d206916028dcf4658e3b9937a7952152c9d030  atlas-probe
2c2d86b3a34062160afc48b22020f3601a44fff24e18ea03e1026a78efcf4482  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
78fc5a1e0765ae93586b5c3779650e279c2e69f18c233bf5387b7ad2fa2a8964  sudoers.atlas-ro
```
