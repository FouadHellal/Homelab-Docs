"""`--sanitize`: deterministic pseudonymisation for public screenshots and demos (SPEC §10).

* IPv4: each /24 maps to a distinct 10.X.Y.0/24 (keyed), last octet kept, so subnet
  structure and "same network" relations survive while the real addressing does not.
* IPv6: each /64 maps to 2001:db8:XXXX:YYYY::/64 and the interface id is hashed too
  (EUI-64 IIDs embed the MAC).
* MACs: 02:xx:xx:xx:xx:xx (locally administered), keyed hash.
* Names (hosts, entities, SSIDs, compose projects, domains): `<kind>-NN`, numbered in a stable
  order. Owner/purpose/notes/links/serials/machine-ids are dropped or hashed.
A final regex pass rewrites any address or known name left inside free text (summaries,
cron lines, labels), so the output is safe even where the structure is unknown.
"""

import hashlib
import hmac
import ipaddress
import re
from collections.abc import Iterable
from typing import Any, Final

IPV4_RE: Final = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE: Final = re.compile(
    r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?(?![0-9A-Za-z:])"
)
MAC_RE: Final = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
HEX_ID_RE: Final = re.compile(r"\b[0-9a-f]{32}\b")  # machine-ids
DROP_KEYS: Final = frozenset(
    {"owner", "purpose", "notes", "links", "description", "serial", "comment", "comments", "gecos"}
)


class Sanitizer:
    def __init__(self, key: bytes) -> None:
        self._key = key
        self._names: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._v4: dict[str, str] = {}
        self._used_v4: set[str] = set()

    def _h(self, text: str, n: int = 8) -> bytes:
        return hmac.new(self._key, text.encode(), hashlib.sha256).digest()[:n]

    # ------------------------------------------------------------------ names

    def register(self, names: Iterable[str], kind: str) -> None:
        """Assign `<kind>-NN` pseudonyms in a stable (sorted) order."""
        for name in sorted({n for n in names if n and len(n) >= 3}):
            if name not in self._names:
                self._counters[kind] = self._counters.get(kind, 0) + 1
                self._names[name] = f"{kind}-{self._counters[kind]:02d}"

    def name(self, text: str) -> str:
        return self._names.get(text, self.text(text))

    # ------------------------------------------------------------------ addresses

    def ipv4(self, ip: str) -> str:
        a, b, c, d = ip.split(".")
        prefix = f"{a}.{b}.{c}"
        if prefix not in self._v4:
            h = self._h(f"v4:{prefix}", 2)
            x, y = h[0], h[1]
            while f"10.{x}.{y}" in self._used_v4:
                y = (y + 1) % 256
                x = (x + (y == 0)) % 256
            self._v4[prefix] = f"10.{x}.{y}"
            self._used_v4.add(self._v4[prefix])
        return f"{self._v4[prefix]}.{d}"

    def ipv6(self, text: str) -> str:
        addr, _, plen = text.partition("/")
        try:
            ip = ipaddress.IPv6Address(addr)
        except ValueError:
            return text
        if ip.is_loopback or ip.is_unspecified:
            return text
        net = int(ip) >> 64
        iid = int(ip) & ((1 << 64) - 1)
        hn = int.from_bytes(self._h(f"v6net:{net}", 4), "big")
        hi = int.from_bytes(self._h(f"v6iid:{iid}", 2), "big") if iid else 0
        new = ipaddress.IPv6Address((0x20010DB8 << 96) | (hn << 64) | hi).compressed
        return f"{new}/{plen}" if plen else new

    def mac(self, mac: str) -> str:
        h = self._h(f"mac:{mac.lower()}", 5)
        return "02:" + ":".join(f"{b:02x}" for b in h)

    def text(self, s: str) -> str:
        def v4(m: re.Match[str]) -> str:
            ip = m.group(0)
            try:
                parsed = ipaddress.IPv4Address(ip)
            except ValueError:
                return ip
            return ip if parsed.is_loopback or parsed.is_unspecified else self.ipv4(ip)

        # IPv6 first (validated, so a bare MAC is left alone), then MACs: a MAC may follow a
        # colon (`mac:aa:bb:...` entity keys) and must not clip the tail of an IPv6 address.
        s = IPV6_RE.sub(lambda m: self.ipv6(m.group(0)), s)
        s = MAC_RE.sub(lambda m: self.mac(m.group(0)), s)
        s = IPV4_RE.sub(v4, s)
        s = HEX_ID_RE.sub(lambda m: self._h(m.group(0), 16).hex(), s)
        for real in sorted(self._names, key=len, reverse=True):
            if real in s:
                s = s.replace(real, self._names[real])
        return s

    # ------------------------------------------------------------------ structures

    def data(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.name(obj)
        if isinstance(obj, dict):
            return {
                self.text(str(k)): self.data(v) for k, v in obj.items() if str(k) not in DROP_KEYS
            }
        if isinstance(obj, list | tuple):
            return [self.data(v) for v in obj]
        return obj
