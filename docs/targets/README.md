# Target setup artifacts (generated, review before installing)

Probe version **1.1.0**. Regenerate with `uv run atlas targets render`.
Do not edit these files: the collector pins the probe's SHA-256 and `atlas doctor`
reports any mismatch. Step-by-step instructions come in docs/SETUP-TARGETS.md (M7).

| File | Install as | Owner / mode |
|---|---|---|
| `atlas-probe` | `/usr/local/libexec/atlas-probe` | root:root 0755 |
| `atlas-probe-gate` | `/usr/local/libexec/atlas-probe-gate` | root:root 0755 |
| `sudoers.atlas-ro` | `/etc/sudoers.d/atlas-ro` | root:root 0440 (visudo -cf) |
| `authorized_keys.example` | `~atlas-ro/.ssh/authorized_keys` | atlas-ro 0600, dir 0700, owned by root is fine |

User: `atlas-ro`, a system account with no password (`passwd -l`), no docker group, no other sudo rights.
Implemented sections: `cron`, `docker`, `net`, `os`, `packages`, `ports`, `services`, `storage`, `users`, `version`. `pi` exits 3 until M4.

Debian/Ubuntu only (systemd ≥ 246, iproute2, util-linux, dpkg).

## SHA-256

```
ec1301f7b12096bed3f3a48b9c49a72f75445c7d76c40c1d5b365f5f76f42bab  atlas-probe
54a36d87175081bb27005274f9da0834e89bbcb17f08448ad996279c61f37d1b  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
9b83bc75ecf3a563629b8c19117b2855c3fdd2f11723607c5db74038cb77e4f6  sudoers.atlas-ro
```
