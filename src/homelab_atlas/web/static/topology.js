// atlas topology v3 (ADR-030/031): Proxmox flow / network / VLAN views on Cytoscape.
// Proxmox view: one box per node; inside, the node (hub) -> its bridges -> its guests, wired by
// the bridge each NIC uses, with traffic pulses on running guests (inspired by ProxMenux's
// network flow; our own code). Strict CSP: no inline handlers, no eval, no innerHTML with data.
(function () {
  "use strict";

  var cy = null;
  var el = null;
  var raw = [];
  var hidden = {};          // id -> true (hidden by the user)
  var pinned = null;        // node kept highlighted
  var layoutName = "auto";
  var showIps = true;

  // ------------------------------------------------------------ helpers
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function $(id) { return document.getElementById(id); }
  function make(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function csrf() {
    try { return JSON.parse(document.body.getAttribute("hx-headers") || "{}")["X-CSRF-Token"] || ""; }
    catch (e) { return ""; }
  }
  function flow() { return el && el.dataset.view === "logical"; }
  function copy(text, what) {
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () { toast(what + " copied"); });
  }
  function fmtUptime(s) {
    if (!s) return null;
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
    return d ? d + " d " + h + " h" : h + " h";
  }

  // Small monochrome icons, colour baked in at render time (data: URIs are allowed by the CSP).
  var ICON_PATHS = {
    server: '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>',
    vm: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
    lxc: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>',
    container: '<rect x="4" y="7" width="16" height="12" rx="1.5"/><path d="M8 7V4h8v3"/>',
    node: '<rect x="2" y="3" width="20" height="6" rx="1.5"/><rect x="2" y="11" width="20" height="6" rx="1.5"/><path d="M6 6h.01M6 14h.01M10 21h4"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9.5" y="9.5" width="5" height="5" rx=".8"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
    bridge: '<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="19" r="2.2"/><circle cx="19" cy="19" r="2.2"/><path d="M12 7.2v4.3M12 11.5L6.4 17.2M12 11.5l5.6 5.7"/>',
    gateway: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    switch: '<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/>',
    ap: '<path d="M5 12a10 10 0 0 1 14 0M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>',
    nas: '<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M9 7h6M9 11h6M9 15h6"/>',
    device: '<circle cx="12" cy="12" r="4"/>',
    pi: '<rect x="4" y="5" width="16" height="14" rx="2"/><path d="M8 9h3v3H8zM14 9h2M14 13h2M8 15h8"/>'
  };
  var iconCache = {};
  function icon(name, color) {
    var k = name + color;
    if (!iconCache[k]) {
      var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="' + color +
        '" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' + (ICON_PATHS[name] || ICON_PATHS.device) + "</svg>";
      iconCache[k] = "data:image/svg+xml;utf8," + encodeURIComponent(svg);
    }
    return iconCache[k];
  }
  function iconFor(d) {
    var k = d.kind;
    if (k === "pve-vm") return "vm";
    if (k === "pve-lxc") return "lxc";
    if (k === "pve-hub") return "cpu";
    if (k === "pve-node") return "node";
    if (k === "bridge") return "bridge";
    if (k === "container") return "container";
    if (k === "gateway" || k === "switch" || k === "ap" || k === "nas") return k;
    if (k === "linux-host") return d.category === "pi" || (d.os || "").indexOf("Raspbian") >= 0 ? "pi" : "server";
    if (d.category === "pi") return "pi";
    if (d.category === "vm") return "vm";
    if (d.infra) return "server";
    return "device";
  }
  // Kind colours, ProxMenux-like: node orange, VM purple, LXC cyan, bridge teal.
  function kindColor(d) {
    return {
      "pve-hub": css("--c-hypervisor"), "pve-vm": css("--c-vpn"), "pve-lxc": css("--c-dns"),
      "bridge": css("--c-inventory"), "linux-host": css("--c-home"), "nas": css("--c-files"),
      "container": css("--c-containers")
    }[d.kind] || css("--muted");
  }
  function statusColor(s) {
    if (s === "running" || s === "known" || s === "ok" || s === "identified") return css("--ok");
    if (s === "stopped") return css("--muted");
    if (s === "missing" || s === "failed") return css("--bad");
    if (s === "unknown" || s === "unscanned") return css("--info");
    return css("--line");
  }
  var CAT_COLORS = { personal: "--info", iot: "--warn", unknown: "--muted" };
  function isOff(d) { return d.status === "stopped" || d.status === "unscanned" || d.status === "unknown" || d.idle; }

  // ------------------------------------------------------------ style
  function label(n) {
    var d = n.data();
    if (n.isParent()) return d.label;
    if (d.kind === "bridge") return d.sub ? d.label + "\n" + d.sub : d.label;
    if (d.kind === "container") return d.label;
    return showIps && d.ip ? d.label + "\n" + d.ip : d.label;
  }
  function style() {
    var fg = css("--fg"), muted = css("--muted"), card = css("--card"), line = css("--line"),
        accent = css("--accent"), bg = css("--bg");
    return [
      { selector: "node", style: {
          "label": label,
          "color": fg, "font-size": 11, "font-family": css("--font"), "line-height": 1.35,
          "text-wrap": "wrap", "text-max-width": 122, "text-overflow-wrap": "anywhere", "min-zoomed-font-size": 6,
          "background-color": card, "border-width": 1.5, "border-color": line,
          "shape": "round-rectangle", "width": 136, "height": 60,
          "text-valign": "center", "text-halign": "center", "text-margin-y": 10,
          "background-image": function (n) { return icon(iconFor(n.data()), fg); },
          "background-width": 18, "background-height": 18, "background-position-y": 8,
          "background-clip": "none", "background-image-opacity": 0.9,
          "underlay-color": accent, "underlay-opacity": 0, "underlay-padding": 6, "underlay-shape": "round-rectangle",
          "transition-property": "opacity, underlay-opacity", "transition-duration": "180ms" } },
      { selector: "node[status]", style: { "border-color": function (n) { return statusColor(n.data("status")); } } },
      { selector: "node[status = 'unscanned'], node[status = 'unknown']", style: { "border-style": "dashed", "color": muted } },
      { selector: "node[status = 'stopped']", style: { "color": muted, "background-image-opacity": 0.45 } },
      { selector: "node[kind = 'container']", style: {
          "width": 96, "height": 26, "font-size": 9, "text-max-width": 82, "text-margin-y": 0, "text-margin-x": 6,
          "background-width": 11, "background-height": 11, "background-position-x": 7, "background-position-y": "50%",
          "border-color": function (n) { return n.data("status") === "gone" ? css("--warn") : css("--c-containers"); } } },
      { selector: "node[kind = 'unknown-device'], node[kind = 'unifi-device'], node[category]", style: {
          "width": 112, "height": 46, "font-size": 10, "text-max-width": 100 } },
      { selector: "node[category][!infra]", style: {
          "border-color": function (n) { return css(CAT_COLORS[n.data("category")] || "--muted"); }, "border-style": "dotted" } },
      { selector: "node[kind = 'gateway'], node[kind = 'switch'], node[kind = 'ap']", style: {
          "border-color": accent, "border-width": 2, "font-weight": "bold" } },

      // Proxmox flow view: round nodes, label underneath, colour by kind.
      { selector: "node.flow", style: {
          "shape": "ellipse", "width": 46, "height": 46, "border-width": 2,
          "border-color": function (n) { return kindColor(n.data()); },
          "background-color": bg, "background-image": function (n) { return icon(iconFor(n.data()), kindColor(n.data())); },
          "background-width": 20, "background-height": 20, "background-position-y": "50%",
          "text-valign": "bottom", "text-halign": "center", "text-margin-y": 6, "font-size": 10,
          "font-family": css("--mono"), "text-max-width": 118, "underlay-shape": "ellipse", "underlay-padding": 7,
          "underlay-color": function (n) { return kindColor(n.data()); } } },
      { selector: "node.flow[kind = 'pve-hub']", style: {
          "width": 70, "height": 70, "border-width": 3, "background-width": 30, "background-height": 30,
          "font-size": 12, "font-weight": "bold", "underlay-opacity": 0.12, "font-family": css("--font") } },
      { selector: "node.flow[kind = 'bridge']", style: {
          "width": 34, "height": 34, "background-width": 16, "background-height": 16, "font-size": 9.5,
          "text-valign": "top", "text-margin-y": -6 } },
      { selector: "node.flow[kind = 'container']", style: {
          "shape": "round-rectangle", "width": 104, "height": 22, "border-width": 1, "font-size": 9,
          "text-valign": "center", "text-halign": "center", "text-margin-y": 0, "text-margin-x": 6,
          "background-width": 10, "background-height": 10, "background-position-x": 7, "background-position-y": "50%",
          "font-family": css("--font") } },
      { selector: "node.flow.off", style: { "opacity": 0.55, "border-style": "dashed", "color": muted } },
      { selector: "node.flow[status = 'running']", style: { "underlay-opacity": 0.1 } },

      { selector: ":parent", style: {
          "shape": "round-rectangle", "background-color": accent, "background-opacity": 0.04,
          "border-width": 1, "border-color": line, "padding": 30, "text-valign": "top", "text-halign": "center",
          "text-margin-x": 0, "text-margin-y": -8, "font-weight": "600", "font-size": 12, "color": muted,
          "background-image": "none", "text-wrap": "none", "font-family": css("--font") } },
      { selector: "node[kind = 'pve-node']:parent", style: {
          "border-color": css("--c-hypervisor"), "border-width": 1.5, "background-color": css("--c-hypervisor"),
          "background-opacity": 0.045, "color": fg, "font-size": 13, "corner-radius": 14 } },
      { selector: "node[kind = 'pve-cluster'], node[kind = 'group'], node[kind = 'vlan']", style: {
          "background-opacity": 0.02, "border-style": "dashed", "font-size": 14 } },

      { selector: "edge", style: {
          "width": 1.4, "line-color": line, "curve-style": "bezier", "target-arrow-shape": "none",
          "opacity": 0.9, "transition-property": "opacity, line-color, width", "transition-duration": "180ms" } },
      { selector: "edge.flow", style: {
          "curve-style": "taxi", "taxi-direction": "rightward", "taxi-turn": "50%", "width": 2,
          "line-color": muted, "line-opacity": 0.55, "font-size": 9, "color": fg, "text-background-color": bg,
          "text-background-opacity": 1, "text-background-padding": 2, "text-background-shape": "round-rectangle" } },
      { selector: "edge.flow[kind = 'nic'], edge.flow[kind = 'nic2']", style: {
          "taxi-direction": "downward", "taxi-turn": 26, "taxi-turn-min-distance": 6 } },
      { selector: "edge.flow.hl", style: { "label": function (e) { return e.data("label") || ""; } } },
      { selector: "edge.flow.live", style: {
          "line-fill": "linear-gradient", "line-gradient-stop-colors": [muted, muted, muted], "line-opacity": 0.8,
          "line-gradient-stop-positions": [0, 50, 100] } },
      { selector: "edge[kind = 'nic2']", style: { "line-style": "dashed", "line-dash-pattern": [4, 4] } },
      { selector: "edge[kind = 'uplink']", style: { "width": 2, "line-color": muted, "line-style": "dashed", "line-dash-pattern": [6, 4] } },
      { selector: "edge[kind = 'wireless']", style: { "line-style": "dotted" } },
      { selector: "edge[kind = 'runs']", style: { "line-style": "dashed", "line-dash-pattern": [3, 3], "curve-style": "taxi", "taxi-direction": "downward" } },
      { selector: ".faded", style: { "opacity": 0.12 } },
      { selector: "node.hl", style: { "underlay-opacity": 0.25 } },
      { selector: "edge.hl", style: { "line-color": accent, "width": 2.6, "opacity": 1 } },
      { selector: "node:selected", style: { "underlay-opacity": 0.35, "border-width": 3 } },
      { selector: ".gone-hidden", style: { "display": "none" } },
      { selector: "core", style: { "active-bg-color": accent, "selection-box-color": accent } },
      { selector: "node.match", style: { "underlay-opacity": 0.45, "underlay-color": css("--warn") } }
    ];
  }

  // ------------------------------------------------------------ layouts
  // Our own visibility test: cytoscape's visible() lags right after a class toggle.
  function shown(e) {
    if (e.hasClass("gone-hidden")) return false;
    if (e.isEdge()) return shown(e.source()) && shown(e.target());
    return e.ancestors().filter(function (a) { return a.hasClass("gone-hidden"); }).empty();
  }
  function byLabel(a, b) { return String(a.data("label")).localeCompare(String(b.data("label"))); }
  function containersOf(id) {
    return cy.nodes("[kind = 'container']").filter(function (c) { return c.data("host") === id && shown(c); });
  }

  // Proxmox flow: clusters and nodes top to bottom. In a node box the node (hub) sits on the
  // left, its bridges in a column next to it, and each bridge's guests in rows to the right,
  // fed by a bus under the bridge. Odd rows are shifted by half a column so the drops to
  // the second row pass between the guests of the first. Containers stack under their guest.
  function tidyProxmox() {
    var pos = {}, GW = 168, GH = 128, COLS = 7, CH = 32, y = 0;
    var GX = 420, BUS = 104;  // first guest column; guests start this far below their bridge
    function guestRows(guests, x0, y0) {
      var h = 0;
      for (var r = 0; r * COLS < guests.length; r++) {
        var extra = 0, shift = (r % 2) * GW / 2;
        guests.slice(r * COLS, (r + 1) * COLS).forEach(function (g, i) {
          pos[g.id()] = { x: x0 + shift + i * GW, y: y0 + h };
          var ctr = containersOf(g.id());
          ctr.forEach(function (c, k) { pos[c.id()] = { x: x0 + shift + i * GW, y: y0 + h + 84 + k * CH }; });
          if (ctr.length) extra = Math.max(extra, ctr.length * CH + 26);
        });
        h += GH + extra;
      }
      return Math.max(h, GH);
    }
    var clusters = cy.nodes("[kind = 'pve-cluster']").filter(shown).sort(byLabel);
    clusters.forEach(function (cl) {
      cl.children("[kind = 'pve-node']").filter(shown).sort(byLabel).forEach(function (nd) {
        var hub = nd.children("[kind = 'pve-hub']");
        var bridges = nd.children("[kind = 'bridge']").filter(shown).sort(byLabel);
        var guests = nd.children().filter(function (g) {
          return shown(g) && (g.data("kind") === "pve-vm" || g.data("kind") === "pve-lxc");
        }).sort(function (a, b) { return (a.data("vmid") || 0) - (b.data("vmid") || 0); });
        var names = bridges.map(function (b) { return b.data("label"); });
        var groups = bridges.map(function (b) {
          return { bridge: b, guests: guests.filter(function (g) { return g.data("bridge") === b.data("label"); }) };
        });
        var loose = guests.filter(function (g) { return names.indexOf(g.data("bridge")) < 0; });
        var top = y, cur = y;
        groups.filter(function (g) { return g.guests.length; }).forEach(function (g) {
          pos[g.bridge.id()] = { x: 220, y: cur };
          cur += BUS + guestRows(g.guests, GX, cur + BUS) + 24;
        });
        if (loose.length) cur += guestRows(loose, GX, cur + BUS / 2) + BUS / 2 + 24;
        groups.filter(function (g) { return !g.guests.length; }).forEach(function (g) {
          pos[g.bridge.id()] = { x: 220, y: cur };
          cur += 86;
        });
        var hubY = top + Math.max(0, cur - top - GH) / 2;
        if (hub.length) pos[hub.id()] = { x: 0, y: hubY };
        var hubC = containersOf("hub:" + nd.id());
        hubC.forEach(function (c, k) { pos[c.id()] = { x: 0, y: hubY + 96 + k * CH }; });
        y = Math.max(cur, hubY + 96 + hubC.length * CH + 30, top + 140) + 120;
      });
      y += 40;
    });
    var others = cy.nodes("#group\\:other").children().filter(function (g) { return shown(g) && g.data("kind") !== "container"; }).sort(byLabel);
    if (others.length) guestRows(others, 0, y + 30);
    return pos;
  }

  function vlanPositions() {
    var groups = {}, pos = {}, x0 = 0;
    cy.nodes().forEach(function (n) {
      var p = n.data("parent");
      if (p && shown(n)) (groups[p] = groups[p] || []).push(n.id());
    });
    Object.keys(groups).sort().forEach(function (g) {
      var ids = groups[g], cols = Math.max(1, Math.ceil(Math.sqrt(ids.length)));
      ids.forEach(function (id, i) { pos[id] = { x: x0 + (i % cols) * 130, y: Math.floor(i / cols) * 70 }; });
      x0 += cols * 130 + 160;
    });
    return pos;
  }

  // Nodes hidden since the graph was built have no rendered position to animate from:
  // put them in place directly, animate the rest.
  var laidOut = {};
  function jumpNew(positions) {
    cy.nodes().forEach(function (n) {
      if (!shown(n)) return;
      if (!laidOut[n.id()] && positions[n.id()]) n.position(positions[n.id()]);
      laidOut[n.id()] = true;
    });
  }

  // ------------------------------------------------------------ saved layouts (per browser)
  // Drag nodes where you like: positions are kept per view in localStorage and applied over
  // the tidy layout. "Reset my layout" forgets them; "Lock layout" stops accidental drags.
  function posKey() { return "atlas-topo-pos:" + el.dataset.view; }
  function savedPositions() {
    try { return JSON.parse(localStorage.getItem(posKey()) || "{}") || {}; } catch (e) { return {}; }
  }
  function storePositions(map) {
    try { localStorage.setItem(posKey(), JSON.stringify(map)); } catch (e) { /* private mode */ }
  }
  function rememberDrag(n) {
    var map = savedPositions();
    var moved = n.isParent() ? n.descendants().filter(function (d) { return !d.isParent(); }) : n;
    moved.forEach(function (m) { var p = m.position(); map[m.id()] = { x: Math.round(p.x), y: Math.round(p.y) }; });
    storePositions(map);
  }
  function hasSaved() { return Object.keys(savedPositions()).length > 0; }
  function locked() { try { return localStorage.getItem("atlas-topo-lock") === "1"; } catch (e) { return false; } }
  function setLocked(on) {
    try { localStorage.setItem("atlas-topo-lock", on ? "1" : "0"); } catch (e) { /* private mode */ }
    if (cy) cy.autoungrabify(on);
    toast(on ? "Layout locked: nodes can't be dragged." : "Layout unlocked: drag nodes to arrange them.");
  }
  function withSaved(positions) {
    if (layoutName !== "auto") return positions;
    var saved = savedPositions(), out = {};
    Object.keys(positions).forEach(function (k) { out[k] = positions[k]; });
    Object.keys(saved).forEach(function (k) { out[k] = saved[k]; });
    // Containers follow their (moved) machine, keeping their place under it.
    cy.nodes("[kind = 'container']").forEach(function (c) {
      var h = c.data("host");
      if (saved[c.id()] || !saved[h] || !positions[h] || !positions[c.id()]) return;
      out[c.id()] = { x: saved[h].x + positions[c.id()].x - positions[h].x,
                      y: saved[h].y + positions[c.id()].y - positions[h].y };
    });
    return out;
  }

  function runLayout(animate) {
    var view = el.dataset.view, opts;
    var vis = cy.elements().filter(shown);
    if (layoutName === "organic") {
      opts = { name: "cose", animate: animate, animationDuration: 600, nodeRepulsion: 9000,
               idealEdgeLength: 90, nestingFactor: 1.1, padding: 30, randomize: false };
    } else if (layoutName === "circle") {
      opts = { name: "concentric", animate: animate, animationDuration: 500, padding: 30, minNodeSpacing: 18,
               concentric: function (n) { return n.degree() + (n.isParent() ? 5 : 0); }, levelWidth: function () { return 2; } };
    } else if (view === "logical") {
      var p = withSaved(tidyProxmox());
      jumpNew(p);
      opts = { name: "preset", positions: function (n) { return p[n.id()]; }, animate: animate, animationDuration: 450, padding: 40, fit: true };
    } else if (view === "vlan") {
      var q = withSaved(vlanPositions());
      jumpNew(q);
      opts = { name: "preset", positions: function (n) { return q[n.id()]; }, animate: animate, animationDuration: 450, padding: 30 };
    } else {
      var roots = cy.nodes("[kind = 'gateway']");
      opts = { name: "breadthfirst", directed: true, roots: roots.length ? roots : undefined,
               spacingFactor: 1.15, padding: 30, animate: animate, animationDuration: 500 };
      if (layoutName === "auto" && hasSaved()) {
        opts.stop = function () {
          var saved = savedPositions();
          cy.nodes().forEach(function (n) { if (saved[n.id()] && !n.isParent()) n.position(saved[n.id()]); });
        };
      }
    }
    vis.layout(opts).run();
  }

  // ------------------------------------------------------------ visibility toggles
  function applyFilters() {
    var showCtr = $("topo-containers") ? $("topo-containers").checked : false;
    var showUndoc = $("topo-undocumented") ? $("topo-undocumented").checked : true;
    var showStopped = $("topo-stopped") ? $("topo-stopped").checked : true;
    var everything = $("topo-everything") ? $("topo-everything").checked : true;
    cy.batch(function () {
      cy.nodes().forEach(function (n) {
        var d = n.data(), hide = !!hidden[n.id()];
        if (d.kind === "container" && !showCtr && !n.data("_forced")) hide = true;
        if ((d.status === "unscanned" || (d.documented === false && d.kind !== "bridge" && d.kind !== "pve-hub" && !n.isParent())) && !showUndoc) hide = true;
        if (d.status === "stopped" && !showStopped) hide = true;
        if (d.category && !d.infra && !everything) hide = true;
        n.toggleClass("gone-hidden", hide);
      });
      cy.edges().forEach(function (e) {
        e.toggleClass("gone-hidden", e.source().hasClass("gone-hidden") || e.target().hasClass("gone-hidden"));
      });
      // Empty group boxes would float around with nothing inside.
      cy.nodes(":parent").forEach(function (p) {
        var any = p.children().filter(function (c) { return !c.hasClass("gone-hidden"); }).length;
        if (!any && p.data("kind") !== "pve-node") p.addClass("gone-hidden");
      });
    });
  }

  // ------------------------------------------------------------ highlight
  function clearHighlight() {
    cy.elements().removeClass("faded hl");
  }
  // Path view: the node, what it connects to, and the way up to its hypervisor.
  function hoodOf(node) {
    var hood = node.closedNeighborhood().union(node.ancestors()).union(node.descendants());
    if (flow() && (node.data("kind") === "pve-vm" || node.data("kind") === "pve-lxc")) {
      node.incomers("node").forEach(function (b) { hood = hood.union(b.incomers("node")).union(b.incomers("edge")); });
    }
    if (flow() && node.data("kind") === "bridge") hood = hood.union(node.outgoers());
    return hood.union(hood.connectedEdges().filter(function (e) { return hood.contains(e.source()) && hood.contains(e.target()); }));
  }
  function highlight(node) {
    var hood = hoodOf(node);
    cy.batch(function () {
      cy.elements().not(hood).addClass("faded");
      hood.removeClass("faded").addClass("hl");
    });
  }

  // ------------------------------------------------------------ side panel
  function row(dl, k, v) {
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) return;
    dl.appendChild(make("dt", null, k));
    dl.appendChild(make("dd", null, Array.isArray(v) ? v.join(", ") : v));
  }
  var KIND_LABEL = { "pve-vm": "Virtual machine", "pve-lxc": "LXC container", "pve-node": "Proxmox node",
    "pve-hub": "Proxmox node", "bridge": "Linux bridge", "linux-host": "Machine", "container": "Docker container",
    "nas": "NAS", "gateway": "Gateway", "switch": "Switch", "ap": "Access point", "unknown-device": "Unknown device",
    "pve-cluster": "Proxmox cluster" };
  function pill(status) {
    var cls = status === "running" || status === "known" ? "ok" : status === "stopped" ? "partial"
      : status === "unscanned" || status === "unknown" ? "info" : "failed";
    var text = status === "unscanned" ? "not documented" : status === "unknown" ? "state unknown" : status;
    return make("span", "pill " + cls, text);
  }
  function link(text, href, cls, blank) {
    var a = make("a", cls || "btn ghost", text);
    a.href = href;
    if (blank) { a.target = "_blank"; a.rel = "noopener noreferrer"; }
    return a;
  }
  function gauge(parent, title, value, max, unit) {
    if (!max) return;
    var pct = Math.max(0, Math.min(100, Math.round((value / max) * 100)));
    var g = make("div", "gauge");
    var bar = make("div", "gauge-bar");
    var fill = make("div", "gauge-fill");
    fill.style.width = pct + "%";
    bar.appendChild(fill);
    g.appendChild(make("span", "gauge-k", title));
    g.appendChild(bar);
    g.appendChild(make("span", "gauge-v", value + " / " + max + (unit || "")));
    parent.appendChild(g);
  }
  function showPanel(n) {
    var d = n.data(), body = $("topo-panel-body");
    body.textContent = "";
    if (d.kind === "pve-node" && n.isParent()) { n = n.children("[kind = 'pve-hub']").first(); d = n.data() || d; }
    body.appendChild(make("h2", null, d.label));
    body.appendChild(make("p", "muted small", (KIND_LABEL[d.kind] || d.kind) + (d.vmid ? " " + d.vmid : "") + (d.node ? " · on " + d.node : "")));
    if (d.status && d.kind !== "bridge") body.appendChild(pill(d.status));
    var dl = make("dl", "kv");
    if (d.kind === "bridge") {
      row(dl, "Address", d.sub);
      row(dl, "Ports", d.ports);
      var on = n.outgoers("node").map(function (g) { return g.data("label"); });
      row(dl, "Guests", on.length ? on : "none");
      body.appendChild(dl);
      $("topo-panel").hidden = false;
      return;
    }
    row(dl, "IP", (d.ips && d.ips.length > 1) ? d.ips : d.ip);
    row(dl, "MAC", d.mac);
    row(dl, "OS", d.os);
    if (d.kind === "pve-hub" && d.pve) {
      row(dl, "Proxmox VE", d.pve.version);
      row(dl, "CPU", d.pve.cpu_cores ? d.pve.cpu_cores + " cores" + (d.pve.cpu_model ? " · " + d.pve.cpu_model : "") : null);
      row(dl, "Memory", d.pve.memory_gb ? d.pve.memory_gb + " GB" : null);
      row(dl, "Uptime", fmtUptime(d.pve.uptime_s));
      row(dl, "Bridges", (d.pve.bridges || []).map(function (b) { return b.name; }));
      var box = n.parent();
      if (box && box.length) row(dl, "Guests", box.data("guest_count") + " (" + box.data("running") + " running)");
    }
    row(dl, "Network", d.network ? d.network + (d.vlan !== null && d.vlan !== undefined ? " (VLAN " + d.vlan + ")" : "") : null);
    row(dl, "Uplink", d.uplink);
    row(dl, "CPU / RAM", d.cores ? d.cores + " vCPU" + (d.memory_mb ? " · " + Math.round(d.memory_mb / 102.4) / 10 + " GB" : "") : null);
    if (d.nics && d.nics.length) {
      row(dl, "NICs", d.nics.map(function (x) { return (x.bridge || "?") + (x.vlan !== null && x.vlan !== undefined ? " · VLAN " + x.vlan : "") + (x.mac ? " · " + x.mac : ""); }));
    }
    if (d.documented) row(dl, "Running", (d.services || 0) + " services · " + (d.containers || 0) + " containers · " + (d.ports || 0) + " ports");
    row(dl, "Tags", d.tags);
    row(dl, "Looks like", d.category);
    if (d.pve_from && d.pve_from !== "proxmox") row(dl, "Proxmox data", d.pve_from === "pve-ssh" ? "from the node over SSH" : "from another node's /etc/pve");
    body.appendChild(dl);
    if (d.kind === "pve-hub" && d.pve && d.pve.cpu_load !== null && d.pve.cpu_load !== undefined) {
      gauge(body, "CPU", Math.round(d.pve.cpu_load * 100), 100, "%");
    }
    if (d.apps && d.apps.length) {
      var chips = make("div", "chips");
      d.apps.forEach(function (a) { chips.appendChild(make("span", "chip", a)); });
      body.appendChild(chips);
    }
    if (d.status === "unknown" && (d.kind === "pve-vm" || d.kind === "pve-lxc")) {
      body.appendChild(make("p", "muted small", "Seen in the cluster configuration of another node. Add its own node on Targets (or the Proxmox API) to see whether it runs."));
    } else if (d.documented === false && d.kind !== "container" && d.kind !== "pve-hub") {
      body.appendChild(make("p", "muted small", "atlas doesn't log in to this machine yet, so what runs inside it is unknown. Add it on Targets."));
    }
    var actions = make("div", "actions");
    if (d.key) actions.appendChild(link("Open details", "/entity?key=" + encodeURIComponent(d.key), "btn"));
    if (d.documented) actions.appendChild(link("What runs here", "/running?q=" + encodeURIComponent(d.label)));
    if (d.web) actions.appendChild(link("Open " + (d.web_app || "web UI") + " ↗", d.web, "btn ghost", true));
    if (d.documented === false && d.ip && d.kind !== "pve-hub") {
      actions.appendChild(link("Add as target", "/targets/host?prefill_name=" + encodeURIComponent(d.label || "") + "&prefill_address=" + encodeURIComponent(d.ip)));
    }
    body.appendChild(actions);
    $("topo-panel").hidden = false;
  }

  // ------------------------------------------------------------ context menu
  function menu(items, x, y) {
    var m = $("topo-menu");
    m.textContent = "";
    items.forEach(function (it) {
      if (it === "-") { m.appendChild(make("div", "sep")); return; }
      if (typeof it === "string") { m.appendChild(make("div", "menu-head", it)); return; }
      var b = make("button", "menu-item", it.label);
      b.type = "button";
      b.setAttribute("role", "menuitem");
      if (it.hint) b.appendChild(make("kbd", null, it.hint));
      if (it.disabled) b.disabled = true;
      b.addEventListener("click", function () { hideMenu(); it.run(); });
      m.appendChild(b);
    });
    var rect = el.getBoundingClientRect();
    m.hidden = false;
    var mx = Math.min(x, rect.width - m.offsetWidth - 8), my = Math.min(y, rect.height - m.offsetHeight - 8);
    m.style.left = Math.max(4, mx) + "px";
    m.style.top = Math.max(4, my) + "px";
    var first = m.querySelector("button:not([disabled])");
    if (first) first.focus({ preventScroll: true });
  }
  function hideMenu() { var m = $("topo-menu"); if (m) m.hidden = true; }

  function focusOn(eles) { cy.animate({ fit: { eles: eles, padding: 80 } }, { duration: 450, easing: "ease-in-out-cubic" }); }
  function isolate(n) {
    var keep = hoodOf(n);
    cy.nodes().forEach(function (o) { if (!keep.contains(o) && !o.isParent()) hidden[o.id()] = true; });
    applyFilters(); runLayout(true);
    toast("Showing only " + n.data("label") + " and its links. Right-click the background → Show everything.");
  }
  function setContainers(nodes, on) {
    nodes.forEach(function (h) { containersOf2(h.id()).forEach(function (c) { c.data("_forced", on); }); });
    applyFilters(); runLayout(true);
  }
  function containersOf2(id) { return cy.nodes("[kind = 'container']").filter(function (c) { return c.data("host") === id; }); }
  function postScan(name) {
    var body = new URLSearchParams();
    body.set("name", name);
    fetch("/targets/scan", { method: "POST", credentials: "same-origin", body: body,
                             headers: { "X-CSRF-Token": csrf(), "HX-Request": "true" } })
      .then(function (r) { toast(r.ok ? "Scan of " + name + " queued: refresh in a minute." : "Scan not available."); })
      .catch(function () { toast("Could not start a scan."); });
  }

  function nodeMenu(n, pos) {
    var d = n.data(), items = [];
    if (n.isParent() && d.kind === "pve-node") { n = n.children("[kind = 'pve-hub']").first(); d = n.data() || d; }
    items.push(d.label);
    if (d.key) items.push({ label: "Open details", hint: "dbl-click", run: function () { window.location.href = "/entity?key=" + encodeURIComponent(d.key); } });
    if (d.documented) items.push({ label: "What runs here", run: function () { window.location.href = "/running?q=" + encodeURIComponent(d.label); } });
    if (d.kind === "pve-hub" && d.ip) items.push({ label: "Open Proxmox web UI ↗", run: function () { window.open("https://" + d.ip + ":8006", "_blank", "noopener"); } });
    else if (d.web) items.push({ label: "Open " + (d.web_app || "web UI") + " ↗", run: function () { window.open(d.web, "_blank", "noopener"); } });
    if (d.scan_target) items.push({ label: "Scan this machine now", disabled: !csrf(), run: function () { postScan(d.scan_target); } });
    items.push("-");
    if (d.ip) items.push({ label: "Copy IP  " + d.ip, run: function () { copy(d.ip, "IP"); } });
    if (d.mac) items.push({ label: "Copy MAC", run: function () { copy(d.mac, "MAC"); } });
    if (d.ip && d.kind !== "bridge") items.push({ label: "Copy SSH command", run: function () { copy("ssh " + d.ip, "SSH command"); } });
    items.push("-");
    items.push({ label: "Focus", hint: "zoom", run: function () { focusOn(hoodOf(n)); } });
    items.push({ label: pinned === n ? "Stop highlighting" : "Highlight path", run: function () {
      if (pinned === n) { pinned = null; clearHighlight(); } else { pinned = n; clearHighlight(); highlight(n); } } });
    items.push({ label: "Show only this", run: function () { isolate(n); } });
    var ctr = containersOf2(n.id());
    if (ctr.length) {
      var visible = ctr.filter(function (c) { return !c.hasClass("gone-hidden"); }).length > 0;
      items.push({ label: (visible ? "Hide " : "Show ") + ctr.length + " containers", run: function () { setContainers(n, !visible); } });
    }
    if (d.kind === "pve-hub") {
      var guests = n.parent().children("[kind = 'pve-vm'], [kind = 'pve-lxc']");
      items.push({ label: "Show containers of all guests", run: function () { setContainers(guests.union(n), true); } });
    }
    items.push({ label: "Hide this", run: function () { hidden[n.id()] = true; applyFilters(); runLayout(true); } });
    if (d.documented === false && d.ip && d.kind !== "pve-hub") {
      items.push("-");
      items.push({ label: "Add as target…", run: function () {
        window.location.href = "/targets/host?prefill_name=" + encodeURIComponent(d.label || "") + "&prefill_address=" + encodeURIComponent(d.ip || ""); } });
    }
    menu(items, pos.x, pos.y);
  }

  function backgroundMenu(pos) {
    var nHidden = Object.keys(hidden).length;
    var hosts = cy.nodes().filter(function (n) { return containersOf2(n.id()).length > 0; });
    menu([
      "View",
      { label: "Fit to screen", hint: "F", run: fit },
      { label: "Re-arrange", hint: "R", run: function () { runLayout(true); } },
      { label: "Show everything" + (nHidden ? " (" + nHidden + " hidden)" : ""), disabled: !nHidden, run: function () { hidden = {}; applyFilters(); runLayout(true); } },
      { label: "Show all containers", disabled: !hosts.length, run: function () { setContainers(hosts, true); } },
      { label: "Hide all containers", disabled: !hosts.length, run: function () { setContainers(hosts, false); } },
      { label: showIps ? "Hide IP addresses" : "Show IP addresses", run: function () { showIps = !showIps; cy.style().update(); } },
      { label: locked() ? "Unlock layout" : "Lock layout", run: function () { setLocked(!locked()); } },
      { label: "Reset my layout", disabled: !hasSaved(), run: function () { storePositions({}); laidOut = {}; runLayout(true); toast("Layout reset."); } },
      "-",
      "Layout",
      { label: "Tidy", run: function () { setLayout("auto"); } },
      { label: "Organic", run: function () { setLayout("organic"); } },
      { label: "Rings", run: function () { setLayout("circle"); } },
      "-",
      { label: "Download PNG", run: png },
      { label: "Scan everything now", disabled: !csrf(), run: scanNow }
    ], pos.x, pos.y);
  }

  function fit() { cy.animate({ fit: { eles: cy.elements().filter(shown), padding: 40 } }, { duration: 400 }); }
  function setLayout(name) {
    layoutName = name;
    document.querySelectorAll("[data-layout]").forEach(function (o) { o.classList.toggle("on", o.dataset.layout === name); });
    runLayout(true);
  }

  function scanNow() {
    fetch("/scan", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf(), "HX-Request": "true" } })
      .then(function (r) { toast(r.status === 202 ? "Scan queued: refresh in a minute." : "Scan not available."); })
      .catch(function () { toast("Could not start a scan."); });
  }

  function toast(msg) {
    var t = make("div", "toast", msg);
    document.body.appendChild(t);
    setTimeout(function () { t.classList.add("out"); }, 2600);
    setTimeout(function () { t.remove(); }, 3200);
  }

  function png() {
    var a = make("a");
    a.href = cy.png({ full: true, scale: 2, bg: css("--bg") });
    a.download = "atlas-topology-" + el.dataset.view + ".png";
    document.body.appendChild(a); a.click(); a.remove();
  }

  // ------------------------------------------------------------ legend
  function legend() {
    var l = $("topo-legend");
    l.textContent = "";
    var items;
    if (flow()) {
      items = [["pve-hub", "Proxmox node"], ["bridge", "bridge"], ["pve-vm", "VM"], ["pve-lxc", "LXC"],
               ["linux-host", "other machine"], ["off", "stopped / unknown"]];
      items.forEach(function (it) {
        var s = make("span", "lg");
        var dot = make("span", "lg-dot round");
        if (it[0] === "off") { dot.style.borderColor = css("--muted"); dot.style.borderStyle = "dashed"; }
        else dot.style.borderColor = kindColor({ kind: it[0] });
        s.appendChild(dot);
        s.appendChild(document.createTextNode(it[1]));
        l.appendChild(s);
      });
      return;
    }
    items = [["running", "running"], ["stopped", "stopped"], ["unscanned", "not documented"], ["failed", "failed"]];
    if (el.dataset.view === "physical") items = [["known", "documented"], ["unscanned", "infrastructure, not documented"], ["missing", "missing"]];
    items.forEach(function (it) {
      var s = make("span", "lg");
      var dot = make("span", "lg-dot");
      dot.style.borderColor = statusColor(it[0]);
      if (it[0] === "unscanned") dot.style.borderStyle = "dashed";
      s.appendChild(dot);
      s.appendChild(document.createTextNode(it[1]));
      l.appendChild(s);
    });
  }

  // ------------------------------------------------------------ animation
  // Dashes crawl along uplinks and "runs" edges; on the Proxmox view a bright pulse travels
  // from bridge to every running guest, like traffic.
  var animTimer = null;
  function animate() {
    if (animTimer) clearInterval(animTimer);
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;
    var off = 0, t = 0;
    var line = css("--muted");
    animTimer = setInterval(function () {
      if (!cy || document.hidden) return;
      off = (off + 1) % 100;
      t = (t + 2) % 140;
      cy.batch(function () {
        cy.edges("[kind = 'uplink'], [kind = 'runs']").style("line-dash-offset", -off);
        cy.edges(".live").forEach(function (e, i) {
          var p = ((t + (i * 23) % 140) % 140) - 20;
          if (p < 1 || p > 99) {
            e.style({ "line-gradient-stop-colors": [line, line, line], "line-gradient-stop-positions": [0, 50, 100] });
            return;
          }
          var c = e.data("pulse");
          e.style({ "line-gradient-stop-colors": [line, c, line],
                    "line-gradient-stop-positions": [Math.max(0, p - 14), p, Math.min(100, p + 14)] });
        });
      });
    }, 50);
  }

  // ------------------------------------------------------------ search
  function search(q) {
    q = (q || "").trim().toLowerCase();
    cy.nodes().removeClass("match");
    if (!q) { if (!pinned) clearHighlight(); return null; }
    var hits = cy.nodes().filter(function (n) {
      var d = n.data();
      return !n.isParent() && [d.label, d.ip, (d.ips || []).join(" "), d.mac, d.os, (d.apps || []).join(" "), d.node, d.sub,
                               (d.tags || []).join(" ")].join(" ").toLowerCase().indexOf(q) >= 0;
    });
    cy.batch(function () {
      cy.elements().addClass("faded");
      hits.union(hits.ancestors()).removeClass("faded");
      hits.addClass("match");
    });
    var c = $("topo-count");
    if (c) c.textContent = hits.length + " found";
    return hits;
  }

  // ------------------------------------------------------------ build
  function build(elements) {
    if (cy) cy.destroy();
    var parentOf = {};
    elements.forEach(function (e) { if (e.data && e.data.parent) parentOf[e.data.id] = e.data.parent; });
    elements = elements.map(function (e) {
      if (e.data && e.data.kind === "container" && parentOf[e.data.host]) {
        return { data: Object.assign({}, e.data, { parent: parentOf[e.data.host] }) };
      }
      return e;
    });
    laidOut = {};
    // Proxmox view: classes go on before the graph exists, so nothing animates from the
    // default tile size (and a hidden tab never shows half-finished transitions).
    if (flow()) {
      var parents = {}, byId = {};
      elements.forEach(function (e) { if (e.data.parent) parents[e.data.parent] = true; byId[e.data.id] = e.data; });
      elements = elements.map(function (e) {
        var d = e.data, cls = [];
        if (d.source === undefined) {
          if (!parents[d.id]) { cls.push("flow"); if (isOff(d)) cls.push("off"); }
        } else if (d.kind !== "runs") {
          cls.push("flow");
          var tgt = byId[d.target] || {};
          if (tgt.status === "running" || (d.kind === "trunk" && tgt.kind === "bridge" && !tgt.idle)) {
            cls.push("live");
            d = Object.assign({}, d, { pulse: kindColor(tgt.kind === "bridge" ? { kind: "bridge" } : tgt) });
          }
        }
        return { data: d, classes: cls.join(" ") };
      });
    }
    cy = window.cytoscape({
      container: el, elements: elements, style: style(), minZoom: 0.12, maxZoom: 3,
      boxSelectionEnabled: false, autoungrabify: false
    });
    applyFilters();
    runLayout(false);
    legend();
    animate();

    cy.on("mouseover", "node", function (e) { if (!pinned && !e.target.isParent()) highlight(e.target); el.classList.add("pointer"); });
    cy.on("mouseout", "node", function () { if (!pinned) clearHighlight(); el.classList.remove("pointer"); });
    cy.on("tap", "node", function (e) { hideMenu(); if (!e.target.isParent() || e.target.data("kind") === "pve-node") showPanel(e.target); });
    cy.on("dbltap", "node", function (e) { var k = e.target.data("key"); if (k) window.location.href = "/entity?key=" + encodeURIComponent(k); });
    cy.on("tap", function (e) { if (e.target === cy) { hideMenu(); $("topo-panel").hidden = true; if (pinned) { pinned = null; clearHighlight(); } } });
    cy.on("cxttap", "node", function (e) { nodeMenu(e.target, e.renderedPosition || e.position); });
    cy.on("cxttap", function (e) { if (e.target === cy) backgroundMenu(e.renderedPosition || e.position); });
    cy.on("pan zoom", hideMenu);
    cy.on("dragfree", "node", function (e) { rememberDrag(e.target); });
    cy.autoungrabify(locked());
  }

  // /topology?focus=<entity key>: open on that machine (from its page's "Show on topology").
  function focusFromUrl() {
    var key = new URLSearchParams(window.location.search).get("focus");
    if (!key || !cy) return;
    var n = cy.nodes().filter(function (x) { return x.id() === key || x.data("key") === key; });
    n = n.filter(function (x) { return !x.isParent(); }).first().length ? n.filter(function (x) { return !x.isParent(); }).first() : n.first();
    if (!n.length) return;
    if (n.data("kind") === "pve-node") n = n.children("[kind = 'pve-hub']").first();
    setTimeout(function () {
      n.select();
      pinned = n;
      highlight(n);
      focusOn(hoodOf(n));
      showPanel(n);
    }, 120);
  }

  function load() {
    el = $("cy");
    if (!el || typeof window.cytoscape !== "function") return;
    fetch(el.dataset.src, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        raw = data.elements || [];
        if (!raw.length) {
          el.textContent = "";
          var box = make("div", "empty");
          box.appendChild(make("p", null, flow()
            ? "No Proxmox data yet."
            : "Nothing to draw yet."));
          box.appendChild(make("p", "muted", flow()
            ? "Add a Proxmox node on Targets (type proxmox-node, with sudo) or the Proxmox API token. One node is enough: it reads the whole cluster from /etc/pve."
            : "Add a UniFi gateway on Targets."));
          box.appendChild(link("Open Targets", "/targets", "btn"));
          el.appendChild(box);
          return;
        }
        build(raw);
        focusFromUrl();
      })
      .catch(function (err) { el.textContent = "Could not load topology: " + err.message; });
  }

  // ------------------------------------------------------------ wiring
  document.addEventListener("DOMContentLoaded", function () {
    load();
    ["topo-containers", "topo-undocumented", "topo-stopped", "topo-everything"].forEach(function (id) {
      var c = $(id);
      if (c) c.addEventListener("change", function () { applyFilters(); runLayout(true); });
    });
    var s = $("topo-search");
    if (s) {
      s.addEventListener("input", function () { search(s.value); });
      s.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          var hits = search(s.value);
          if (hits && hits.length) { focusOn(hits); if (hits.length === 1) showPanel(hits[0]); }
        }
        if (e.key === "Escape") { s.value = ""; search(""); var c = $("topo-count"); if (c) c.textContent = ""; s.blur(); }
      });
    }
    document.querySelectorAll("[data-layout]").forEach(function (b) {
      b.addEventListener("click", function () { if (cy) setLayout(b.dataset.layout); });
    });
    var f = $("topo-fit");
    if (f) f.addEventListener("click", function () { if (cy) fit(); });
    var p = $("topo-png");
    if (p) p.addEventListener("click", function () { if (cy) png(); });
    var close = $("topo-panel-close");
    if (close) close.addEventListener("click", function () { $("topo-panel").hidden = true; });
    document.addEventListener("keydown", function (e) {
      var typing = e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA");
      if (e.key === "Escape") { hideMenu(); var pnl = $("topo-panel"); if (pnl) pnl.hidden = true; }
      if (typing || !cy || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "/" && s) { e.preventDefault(); s.focus(); }
      if (e.key === "f" || e.key === "F") fit();
      if (e.key === "r" || e.key === "R") runLayout(true);
      if (e.key === "c" || e.key === "C") { var box = $("topo-containers"); if (box) { box.checked = !box.checked; applyFilters(); runLayout(true); } }
    });
    document.addEventListener("click", function (e) { var m = $("topo-menu"); if (m && !m.hidden && !m.contains(e.target)) hideMenu(); });
    el = $("cy");
    if (el) el.addEventListener("contextmenu", function (e) { e.preventDefault(); });
  });

  window.atlasTopology = {
    redraw: function () { if (raw.length) { iconCache = {}; build(raw); } },
    graph: function () { return cy; }
  };
})();
