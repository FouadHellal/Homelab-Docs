# Target setup artifacts (generated, review before installing)

Probe version **1.0.0**. Regenerate with `uv run atlas targets render`.
Do not edit these files: the collector pins the probe's SHA-256 and `atlas doctor`
reports any mismatch. Step-by-step instructions come in docs/SETUP-TARGETS.md (M7).

| File | Install as | Owner / mode |
|---|---|---|
| `atlas-probe` | `/usr/local/libexec/atlas-probe` | root:root 0755 |
| `atlas-probe-gate` | `/usr/local/libexec/atlas-probe-gate` | root:root 0755 |
| `sudoers.atlas-ro` | `/etc/sudoers.d/atlas-ro` | root:root 0440 (visudo -cf) |
| `authorized_keys.example` | `~atlas-ro/.ssh/authorized_keys` | atlas-ro 0600, dir 0700, owned by root is fine |

User: `atlas-ro`, a system account with no password (`passwd -l`), no docker group, no other sudo rights.
Implemented sections: `cron`, `net`, `os`, `packages`, `ports`, `services`, `storage`, `users`, `version`. `docker` and `pi` exit 3 until M3/M4.

Debian/Ubuntu only (systemd ≥ 246, iproute2, util-linux, dpkg).

## SHA-256

```
04175ec0d186f7e9fd7d3477909622bd2a1345e81d5aed17c6dcba3f9233a99f  atlas-probe
461bcdccc20da0cc1b4f7cf00e91cf3a5a6c16442278590c7f3f644bfa9965dc  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
3c898f08244509130bd328a57937f3875840843dd3718d8b9748837fc67d2bf9  sudoers.atlas-ro
```
