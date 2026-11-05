# Target setup artifacts (generated, review before installing)

Probe version **1.5.0**. Regenerate with `uv run atlas targets render`.
Do not edit these files: the collector pins the probe's SHA-256 and `atlas doctor`
reports any mismatch. Step-by-step instructions:
[docs/SETUP-TARGETS.md](../SETUP-TARGETS.md).

| File | Install as | Owner / mode |
|---|---|---|
| `atlas-probe` | `/usr/local/libexec/atlas-probe` | root:root 0755 |
| `atlas-probe-gate` | `/usr/local/libexec/atlas-probe-gate` | root:root 0755 |
| `sudoers.atlas-ro` | `/etc/sudoers.d/atlas-ro` | root:root 0440 (visudo -cf) |
| `authorized_keys.example` | `~atlas-ro/.ssh/authorized_keys` | atlas-ro 0600, dir 0700, owned by root is fine |
| `kubernetes-readonly.yaml` | `kubectl apply -f` on a Kubernetes / k3s cluster | read-only ServiceAccount `atlas` (ADR-048) |

User: `atlas-ro`, a system account with no password (`passwd -l`), no docker group, no other sudo rights.
Implemented sections: `cron`, `docker`, `net`, `os`, `packages`, `pi`, `ports`, `procs`, `pve`, `services`, `storage`, `users`, `version`. `pi` needs Raspberry Pi OS (vcgencmd).

Debian/Ubuntu only (systemd ≥ 246, iproute2, util-linux, dpkg).

## SHA-256

```
f39c4ace8df9c3e7e7c72a70da1bd96badcd80d36776de3811c37d7e204b3c2d  atlas-probe
087c913c7221b4d422240c462f93015b63c0330a7d428145eed6220b58f94e17  atlas-probe-gate
7a65535ffae70a5122dcd3ae4c8b9ac4a4ae652d77530e6ceada6531eb4babea  authorized_keys.example
72010aee576541c9ffcf6d75e3e6167a060e996054581f0c4e19ded033a6f825  kubernetes-readonly.yaml
20d0814153db2db6615040b6125d8077e831e0dede629351342ab7ef073f539a  sudoers.atlas-ro
```
