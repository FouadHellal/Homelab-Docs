# Target setup artifacts (generated, review before installing)

Probe version **1.3.0**. Regenerate with `uv run atlas targets render`.
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
8af92ed379e98904f8c926ad2150b00ea41a20979d6dee06054805198705489b  atlas-probe
7c0d10eb7bc41c598a1e47840e459c00c147a3006bf294c19d98ca7458ebadfa  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
39e5c1039c4cf69cd1f0034ed238d9aea62bf3ed1a4e31ab4c0bc65279f469af  sudoers.atlas-ro
```
