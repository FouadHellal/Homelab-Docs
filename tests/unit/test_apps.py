"""App recognition from services, processes, containers and ports (ADR-029)."""

from pathlib import Path

from homelab_atlas.engine.apps import CATALOG, CATEGORY_LABELS, detect, load_rules
from homelab_atlas.web.views import os_label, top_apps


def _names(apps: list[dict[str, object]]) -> list[object]:
    return [a["name"] for a in apps]


def test_service_unit_recognises_app_and_adds_ports() -> None:
    apps = detect(
        services=[{"unit": "pihole-FTL.service", "active": "active"}],
        ports=[{"port": 53, "process": "pihole-FTL"}, {"port": 4711}, {"port": 80}],
    )
    assert _names(apps) == ["Pi-hole"]
    (pihole,) = apps
    assert pihole["category"] == "dns"
    assert pihole["category_label"] == "DNS"
    assert pihole["ports"] == [53, 4711]
    assert pihole["web_port"] == 80
    assert "service pihole-ftl" in pihole["evidence"]
    # Sockets known but the web port is not among them: no link to a dead UI.
    (quiet,) = detect(
        services=[{"unit": "pihole-FTL.service", "active": "active"}], ports=[{"port": 53}]
    )
    assert quiet["web_port"] is None
    # No socket list at all: offer the default.
    (bare,) = detect(services=[{"unit": "pihole-FTL.service", "active": "active"}])
    assert bare["web_port"] == 80


def test_inactive_units_and_ports_alone_are_not_enough() -> None:
    assert detect(services=[{"unit": "pihole-FTL.service", "active": "inactive"}]) == []
    # A well-known port is weak evidence: 8096 open does not mean Jellyfin.
    assert detect(ports=[{"port": 8096, "process": "python3"}]) == []


def test_templated_and_suffixed_units() -> None:
    apps = detect(
        services=[
            {"unit": "wg-quick@wg0.service", "active": "active"},
            {"unit": "ssh.service", "active": "active"},
        ]
    )
    assert set(_names(apps)) == {"WireGuard", "OpenSSH"}
    assert _names(apps)[-1] == "OpenSSH"  # system apps sort last


def test_process_and_container_evidence() -> None:
    apps = detect(
        processes=[{"comm": "tailscaled", "pid": 10}],
        containers=[
            {"name": "jf", "image": "jellyfin/jellyfin:10.9"},
            {"name": "portainer", "image": "portainer/portainer-ce:2.20"},
        ],
    )
    by = {a["name"]: a for a in apps}
    assert set(by) == {"Tailscale", "Jellyfin", "Portainer"}
    assert by["Jellyfin"]["containers"] == ["jf"]
    assert by["Tailscale"]["evidence"] == ["process tailscaled"]


def test_catalog_is_consistent() -> None:
    names = [a.name for a in CATALOG]
    assert len(names) == len(set(names))
    for a in CATALOG:
        assert a.category in CATEGORY_LABELS, a.name
        assert a.units or a.procs or a.images, a.name  # ports alone never identify an app
        assert a.web is None or 0 < a.web < 65536


def test_os_label() -> None:
    assert os_label("l26") == "Linux"
    assert os_label("win11") == "Windows 11"
    assert os_label("WIN10") == "Windows 10"
    assert os_label("haiku") == "haiku"
    assert os_label(None) is None
    assert os_label("") is None


def test_top_apps_skips_platform_apps() -> None:
    def card(*apps: tuple[str, str]) -> dict[str, object]:
        return {"apps": [{"name": n, "category": c} for n, c in apps]}

    cards = [
        card(("Docker", "containers"), ("Pi-hole", "dns"), ("OpenSSH", "system")),
        card(("Docker", "containers"), ("Pi-hole", "dns"), ("Jellyfin", "media")),
        card(("Proxmox VE", "hypervisor"), ("Grafana", "monitoring")),
    ]
    assert top_apps(cards) == ["Pi-hole", "Grafana", "Jellyfin"]
    assert top_apps(cards, n=1) == ["Pi-hole"]
    assert top_apps([]) == []


def test_custom_rules_file_with_wrong_shape_is_ignored(tmp_path: Path) -> None:
    f = tmp_path / "apps.yaml"
    for text in ("apps: {name: X}\n", "apps: 3\n", "- a\n", ""):
        f.write_text(text, encoding="utf-8")
        assert load_rules(f) == []
