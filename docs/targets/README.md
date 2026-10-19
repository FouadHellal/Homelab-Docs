# Target setup artifacts (generated, review before installing)

Probe version **1.3.1**. Regenerate with `uv run atlas targets render`.
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
8af6c6222762cbf8c5dea159dd9178b0e993f8426197fadb9056acf76ca36859  atlas-probe
c5d224228a9a0fc5f4fcb7b22473bea2d33c77fa01fd6e2541bc47fbfa14a425  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
0b5d34addc6e78faeb663861590909f26aa2f57a452ce0b3f690fb0346155f3d  sudoers.atlas-ro
```
