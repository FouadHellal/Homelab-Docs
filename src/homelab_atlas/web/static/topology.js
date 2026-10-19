// atlas topology v2 (ADR-030): Proxmox / network / VLAN views on Cytoscape.
// Strict CSP: no inline handlers, no eval, no innerHTML with data (everything via textContent).
(function () {
  "use strict";

  var cy = null;
  var el = null;
  var raw = [];
  var hidden = {};          // id -> true (hidden by the user)
  var pinned = null;        // node kept highlighted
  var layoutName = "auto";

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

  // Small monochrome icons, colour baked in at render time (data: URIs are allowed by the CSP).
  var ICON_PATHS = {
    server: '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>',
    vm: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
    lxc: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>',
    container: '<rect x="4" y="7" width="16" height="12" rx="1.5"/><path d="M8 7V4h8v3"/>',
    node: '<rect x="2" y="3" width="20" height="6" rx="1.5"/><rect x="2" y="11" width="20" height="6" rx="1.5"/><path d="M6 6h.01M6 14h.01M10 21h4"/>',
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
    if (k === "pve-node") return "node";
    if (k === "container") return "container";
    if (k === "gateway" || k === "switch" || k === "ap" || k === "nas") return k;
    if (k === "linux-host") return d.category === "pi" ? "pi" : "server";
    if (d.category === "pi") return "pi";
    if (d.category === "vm") return "vm";
    if (d.infra) return "server";
    return "device";
  }
  function statusColor(s) {
    if (s === "running" || s === "known" || s === "ok" || s === "identified") return css("--ok");
    if (s === "stopped") return css("--muted");
    if (s === "unknown" || s === "missing" || s === "failed") return css("--bad");
    if (s === "unscanned") return css("--info");
    return css("--line");
  }
  var CAT_COLORS = { personal: "--info", iot: "--warn", unknown: "--muted" };

  // ------------------------------------------------------------ style
  function style() {
    var fg = css("--fg"), muted = css("--muted"), card = css("--card"), line = css("--line"),
        accent = css("--accent"), bg = css("--bg");
    return [
      { selector: "node", style: {
          "label": function (n) { var d = n.data(); return d.ip && !n.isParent() && d.kind !== "container" ? d.label + "\n" + d.ip : d.label; },
          "color": fg, "font-size": 11, "font-family": css("--font"), "line-height": 1.35,
          "text-wrap": "wrap", "text-max-width": 122, "text-overflow-wrap": "anywhere", "min-zoomed-font-size": 6,
          "background-color": card, "border-width": 1.5, "border-color": line,
          "shape": "round-rectangle", "width": 136, "height": 60,
          "text-valign": "center", "text-halign": "center", "text-margin-y": 10,
          "background-image": function (n) { return icon(iconFor(n.data()), n.data("kind") === "pve-node" ? accent : fg); },
          "background-width": 18, "background-height": 18, "background-position-y": 8,
          "background-clip": "none", "background-image-opacity": 0.9,
          "underlay-color": accent, "underlay-opacity": 0, "underlay-padding": 6, "underlay-shape": "round-rectangle",
          "transition-property": "opacity, underlay-opacity, border-color", "transition-duration": "180ms" } },
      { selector: "node[status]", style: { "border-color": function (n) { return statusColor(n.data("status")); } } },
      { selector: "node[status = 'unscanned']", style: { "border-style": "dashed", "color": muted } },
      { selector: "node[status = 'stopped']", style: { "color": muted, "background-image-opacity": 0.45 } },
      { selector: "node[kind = 'container']", style: {
          "width": 86, "height": 34, "font-size": 9, "text-max-width": 78, "text-margin-y": 7,
          "background-width": 12, "background-height": 12, "background-position-y": 5,
          "border-color": function (n) { return n.data("status") === "gone" ? css("--warn") : css("--ok"); } } },
      { selector: "node[kind = 'unknown-device'], node[kind = 'unifi-device'], node[category]", style: {
          "width": 112, "height": 46, "font-size": 10, "text-max-width": 100 } },
      { selector: "node[category][!infra]", style: {
          "border-color": function (n) { return css(CAT_COLORS[n.data("category")] || "--muted"); }, "border-style": "dotted" } },
      { selector: "node[kind = 'gateway'], node[kind = 'switch'], node[kind = 'ap']", style: {
          "border-color": accent, "border-width": 2, "font-weight": "bold" } },
      { selector: ":parent", style: {
          "shape": "round-rectangle", "background-color": accent, "background-opacity": 0.05,
          "border-width": 1, "border-color": line, "padding": 22, "text-valign": "top", "text-halign": "left",
          "text-margin-x": 0, "text-margin-y": -6, "font-weight": "600", "font-size": 12, "color": muted,
          "background-image": "none", "text-wrap": "none" } },
      { selector: "node[kind = 'pve-node']:parent", style: {
          "border-color": accent, "border-width": 1.5, "background-opacity": 0.07, "color": fg, "font-size": 13 } },
      { selector: "node[kind = 'pve-cluster'], node[kind = 'group'], node[kind = 'vlan']", style: {
          "background-opacity": 0.025, "border-style": "dashed", "font-size": 13 } },
      { selector: "edge", style: {
          "width": 1.4, "line-color": line, "curve-style": "bezier", "target-arrow-shape": "none",
          "opacity": 0.9, "transition-property": "opacity, line-color, width", "transition-duration": "180ms" } },
      { selector: "edge[kind = 'uplink']", style: { "width": 2, "line-color": muted, "line-style": "dashed", "line-dash-pattern": [6, 4] } },
      { selector: "edge[kind = 'wireless']", style: { "line-style": "dotted" } },
      { selector: "edge[kind = 'runs']", style: { "line-style": "dashed", "line-dash-pattern": [3, 3], "curve-style": "taxi", "taxi-direction": "downward" } },
      { selector: ".faded", style: { "opacity": 0.13 } },
      { selector: "node.hl", style: { "underlay-opacity": 0.22, "border-color": accent } },
      { selector: "edge.hl", style: { "line-color": accent, "width": 2.4, "opacity": 1 } },
      { selector: "node:selected", style: { "underlay-opacity": 0.32, "border-width": 2.5, "border-color": accent } },
      { selector: ".gone-hidden", style: { "display": "none" } },
      { selector: "core", style: { "active-bg-color": accent, "selection-box-color": accent } },
      { selector: "node.match", style: { "underlay-opacity": 0.4, "underlay-color": css("--warn") } }
    ].concat(bg ? [] : []);
  }

  // ------------------------------------------------------------ layouts
  // Our own visibility test: cytoscape's visible() lags right after a class toggle.
  function shown(e) {
    if (e.hasClass("gone-hidden")) return false;
    if (e.isEdge()) return shown(e.source()) && shown(e.target());
    return e.ancestors().filter(function (a) { return a.hasClass("gone-hidden"); }).empty();
  }

  function tidyProxmox() {
    // Clusters left→right; nodes left→right inside; guests in a grid inside each node;
    // "Other machines" below; containers in a small row under their machine.
    var pos = {}, W = 152, H = 78;
    var ele = cy.elements();
    var clusters = ele.nodes("[kind = 'pve-cluster']").sort(function (a, b) { return a.data("label") < b.data("label") ? -1 : 1; });
    var x = 0, maxY = 0;
    function containersOf(m) {
      return cy.nodes("[kind = 'container']").filter(function (c) { return c.data("host") === m.id() && !c.hasClass("gone-hidden"); });
    }
    // Machines in rows; each row is as tall as the tallest container stack under it.
    function placeWithContainers(children, x0, y0, colsMax) {
      var n = children.length, cols = Math.max(1, Math.min(colsMax, Math.ceil(Math.sqrt(n * 1.6))));
      var y = y0;
      for (var r = 0; r * cols < n; r++) {
        var extra = 0;
        children.slice(r * cols, (r + 1) * cols).forEach(function (m, i) {
          var px = x0 + i * W;
          pos[m.id()] = { x: px, y: y };
          var ctr = containersOf(m);
          ctr.forEach(function (c, k) { pos[c.id()] = { x: px - 46 + (k % 2) * 92, y: y + 58 + Math.floor(k / 2) * 40 }; });
          if (ctr.length) extra = Math.max(extra, Math.ceil(ctr.length / 2) * 40 + 12);
        });
        y += H + extra;
      }
      return { w: cols * W, h: y - y0 };
    }
    clusters.forEach(function (cl) {
      var nodes = cl.children().sort(function (a, b) { return a.data("label") < b.data("label") ? -1 : 1; });
      var nx = x;
      nodes.forEach(function (nd) {
        var guests = nd.children().filter(function (g) { return shown(g) && g.data("kind") !== "container"; })
          .sort(function (a, b) { return (a.data("vmid") || 0) - (b.data("vmid") || 0); });
        if (!guests.length) { pos[nd.id()] = { x: nx, y: 0 }; nx += W + 60; return; }
        var s = placeWithContainers(guests, nx, 0, 3);
        maxY = Math.max(maxY, s.h);
        nx += s.w + 150;
      });
      x = nx + 60;
    });
    var others = cy.nodes("#group\\:other").children().filter(function (g) { return shown(g) && g.data("kind") !== "container"; });
    if (others.length) placeWithContainers(others, 0, maxY + 140, 6);
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
      var p = tidyProxmox();
      jumpNew(p);
      opts = { name: "preset", positions: function (n) { return p[n.id()]; }, animate: animate, animationDuration: 450, padding: 30, fit: true };
    } else if (view === "vlan") {
      var q = vlanPositions();
      jumpNew(q);
      opts = { name: "preset", positions: function (n) { return q[n.id()]; }, animate: animate, animationDuration: 450, padding: 30 };
    } else {
      var roots = cy.nodes("[kind = 'gateway']");
      opts = { name: "breadthfirst", directed: true, roots: roots.length ? roots : undefined,
               spacingFactor: 1.15, padding: 30, animate: animate, animationDuration: 500 };
    }
    vis.layout(opts).run();
  }

  // ------------------------------------------------------------ visibility toggles
  function applyFilters() {
    var showCtr = $("topo-containers") ? $("topo-containers").checked : false;
    var showUndoc = $("topo-undocumented") ? $("topo-undocumented").checked : true;
    var everything = $("topo-everything") ? $("topo-everything").checked : true;
    cy.batch(function () {
      cy.nodes().forEach(function (n) {
        var d = n.data(), hide = !!hidden[n.id()];
        if (d.kind === "container" && !showCtr && !n.data("_forced")) hide = true;
        if (d.status === "unscanned" && !showUndoc) hide = true;
        if (d.category && !d.infra && !everything) hide = true;
        n.toggleClass("gone-hidden", hide);
      });
      cy.edges().forEach(function (e) {
        e.toggleClass("gone-hidden", e.source().hasClass("gone-hidden") || e.target().hasClass("gone-hidden"));
      });
      // Empty group boxes would float around with nothing inside.
      cy.nodes(":parent").forEach(function (p) { if (!p.children().filter(function (c) { return !c.hasClass("gone-hidden"); }).length && p.data("kind") !== "pve-node") p.addClass("gone-hidden"); });
    });
  }

  // ------------------------------------------------------------ highlight
  function clearHighlight() {
    cy.elements().removeClass("faded hl");
  }
  function highlight(node) {
    var hood = node.closedNeighborhood().union(node.ancestors()).union(node.descendants());
    hood = hood.union(hood.connectedEdges().filter(function (e) { return hood.contains(e.source()) && hood.contains(e.target()); }));
    cy.batch(function () {
      cy.elements().not(hood).addClass("faded");
      hood.removeClass("faded").addClass("hl");
      node.removeClass("hl");
    });
  }

  // ------------------------------------------------------------ side panel
  function row(dl, k, v) {
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) return;
    dl.appendChild(make("dt", null, k));
    dl.appendChild(make("dd", null, Array.isArray(v) ? v.join(", ") : v));
  }
  function showPanel(n) {
    var d = n.data(), body = $("topo-panel-body");
    body.textContent = "";
    var h = make("h2", null, d.label);
    body.appendChild(h);
    var kindLabel = { "pve-vm": "Virtual machine", "pve-lxc": "LXC container", "pve-node": "Proxmox node",
      "linux-host": "Machine", "container": "Docker container", "nas": "NAS", "gateway": "Gateway",
      "switch": "Switch", "ap": "Access point", "unknown-device": "Unknown device", "pve-cluster": "Proxmox cluster" }[d.kind] || d.kind;
    var sub = make("p", "muted small", kindLabel + (d.vmid ? " " + d.vmid : "") + (d.node ? " · on " + d.node : ""));
    body.appendChild(sub);
    if (d.status) {
      var st = make("span", "pill " + (d.status === "running" || d.status === "known" ? "ok" : d.status === "unscanned" ? "info" : d.status === "stopped" ? "partial" : "failed"), d.status === "unscanned" ? "not documented" : d.status);
      body.appendChild(st);
    }
    var dl = make("dl", "kv");
    row(dl, "IP", d.ip);
    row(dl, "MAC", d.mac);
    row(dl, "OS", d.os);
    row(dl, "Network", d.network ? d.network + (d.vlan !== null && d.vlan !== undefined ? " (VLAN " + d.vlan + ")" : "") : null);
    row(dl, "Uplink", d.uplink);
    row(dl, "CPU / RAM", d.cores ? d.cores + " vCPU" + (d.memory_mb ? " · " + Math.round(d.memory_mb / 102.4) / 10 + " GB" : "") : null);
    if (d.documented) row(dl, "Running", (d.services || 0) + " services · " + (d.containers || 0) + " containers · " + (d.ports || 0) + " ports");
    row(dl, "Looks like", d.category);
    body.appendChild(dl);
    if (d.apps && d.apps.length) {
      var chips = make("div", "chips");
      d.apps.forEach(function (a) { chips.appendChild(make("span", "chip", a)); });
      body.appendChild(chips);
    }
    if (d.status === "unscanned" || (d.documented === false && d.kind !== "pve-node" && d.kind !== "container")) {
      body.appendChild(make("p", "muted small", "atlas doesn't log in to this machine yet, so what runs inside it is unknown. Add it on Targets."));
    }
    var actions = make("div", "actions");
    if (d.key) {
      var a = make("a", "btn", "Open details");
      a.href = "/entity?key=" + encodeURIComponent(d.key);
      actions.appendChild(a);
    }
    if (d.web) {
      var w = make("a", "btn ghost", "Open " + (d.web_app || "web UI") + " ↗");
      w.href = d.web; w.target = "_blank"; w.rel = "noopener noreferrer";
      actions.appendChild(w);
    }
    if ((d.status === "unscanned" || d.documented === false) && d.ip && d.kind !== "pve-node") {
      var t = make("a", "btn ghost", "Add as target");
      t.href = "/targets/host?prefill_name=" + encodeURIComponent(d.label || "") + "&prefill_address=" + encodeURIComponent(d.ip);
      actions.appendChild(t);
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
      var b = make("button", "menu-item", it.label);
      b.type = "button";
      b.setAttribute("role", "menuitem");
      if (it.disabled) b.disabled = true;
      b.addEventListener("click", function () { hideMenu(); it.run(); });
      m.appendChild(b);
    });
    var rect = el.getBoundingClientRect();
    m.hidden = false;
    var mx = Math.min(x, rect.width - m.offsetWidth - 8), my = Math.min(y, rect.height - m.offsetHeight - 8);
    m.style.left = Math.max(4, mx) + "px";
    m.style.top = Math.max(4, my) + "px";
  }
  function hideMenu() { $("topo-menu").hidden = true; }

  function nodeMenu(n, pos) {
    var d = n.data(), items = [];
    if (d.key) items.push({ label: "Open details", run: function () { window.location.href = "/entity?key=" + encodeURIComponent(d.key); } });
    if (d.web) items.push({ label: "Open " + (d.web_app || "web UI") + " ↗", run: function () { window.open(d.web, "_blank", "noopener"); } });
    if (d.ip) items.push({ label: "Copy IP " + d.ip, run: function () { if (navigator.clipboard) navigator.clipboard.writeText(d.ip); } });
    items.push("-");
    items.push({ label: "Focus", run: function () { cy.animate({ fit: { eles: n.union(n.descendants()).union(n.neighborhood()), padding: 80 } }, { duration: 450 }); } });
    items.push({ label: pinned === n ? "Stop highlighting" : "Highlight connections", run: function () {
      if (pinned === n) { pinned = null; clearHighlight(); } else { pinned = n; clearHighlight(); highlight(n); } } });
    var ctr = cy.nodes("[kind = 'container']").filter(function (c) { return c.data("host") === n.id(); });
    if (ctr.length) {
      var shown = ctr.filter(function (c) { return !c.hasClass("gone-hidden"); }).length > 0;
      items.push({ label: (shown ? "Hide " : "Show ") + ctr.length + " containers", run: function () {
        ctr.forEach(function (c) { c.data("_forced", !shown); });
        applyFilters(); runLayout(true); } });
    }
    items.push({ label: "Hide this", run: function () { hidden[n.id()] = true; applyFilters(); } });
    if (d.kind === "unknown-device" || d.status === "unscanned" || (d.documented === false && d.ip)) {
      items.push("-");
      items.push({ label: "Add as target…", disabled: !d.ip, run: function () {
        window.location.href = "/targets/host?prefill_name=" + encodeURIComponent(d.label || "") + "&prefill_address=" + encodeURIComponent(d.ip || ""); } });
    }
    menu(items, pos.x, pos.y);
  }

  function backgroundMenu(pos) {
    var anyHidden = Object.keys(hidden).length > 0;
    menu([
      { label: "Fit to screen", run: function () { cy.animate({ fit: { eles: cy.elements(":visible"), padding: 30 } }, { duration: 400 }); } },
      { label: "Re-arrange", run: function () { runLayout(true); } },
      { label: "Show hidden (" + Object.keys(hidden).length + ")", disabled: !anyHidden, run: function () { hidden = {}; applyFilters(); runLayout(true); } },
      "-",
      { label: "Download PNG", run: png },
      { label: "Scan everything now", disabled: !csrf(), run: scanNow }
    ], pos.x, pos.y);
  }

  function scanNow() {
    fetch("/scan", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf(), "HX-Request": "true" } })
      .then(function (r) { toast(r.status === 202 ? "Scan started: refresh in a minute." : r.ok ? "A scan is already running." : "Scan not available."); })
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
    var items = [["running", "running"], ["stopped", "stopped"], ["unscanned", "not documented"], ["unknown", "unknown / failed"]];
    if (el.dataset.view === "physical") items = [["known", "documented"], ["unscanned", "infrastructure, not documented"], ["unknown", "unknown"]];
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

  // ------------------------------------------------------------ edge animation
  var dashTimer = null;
  function animateEdges() {
    if (dashTimer) clearInterval(dashTimer);
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;
    var off = 0;
    dashTimer = setInterval(function () {
      if (!cy || document.hidden) return;
      off = (off + 1) % 100;
      cy.edges("[kind = 'uplink'], [kind = 'runs']").style("line-dash-offset", -off);
    }, 60);
  }

  // ------------------------------------------------------------ search
  function search(q) {
    q = (q || "").trim().toLowerCase();
    cy.nodes().removeClass("match");
    if (!q) { if (!pinned) clearHighlight(); return null; }
    var hits = cy.nodes().filter(function (n) {
      var d = n.data();
      return !n.isParent() && [d.label, d.ip, d.mac, d.os, (d.apps || []).join(" "), d.node].join(" ").toLowerCase().indexOf(q) >= 0;
    });
    cy.batch(function () {
      cy.elements().addClass("faded");
      hits.union(hits.ancestors()).removeClass("faded");
      hits.addClass("match");
    });
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
    cy = window.cytoscape({
      container: el, elements: elements, style: style(),       minZoom: 0.15, maxZoom: 3, boxSelectionEnabled: false, autoungrabify: false
    });
    applyFilters();
    runLayout(false);
    legend();
    animateEdges();

    cy.on("mouseover", "node", function (e) { if (!pinned && !e.target.isParent()) highlight(e.target); el.classList.add("pointer"); });
    cy.on("mouseout", "node", function () { if (!pinned) clearHighlight(); el.classList.remove("pointer"); });
    cy.on("tap", "node", function (e) { hideMenu(); if (!e.target.isParent() || e.target.data("kind") === "pve-node") showPanel(e.target); });
    cy.on("dbltap", "node", function (e) { var k = e.target.data("key"); if (k) window.location.href = "/entity?key=" + encodeURIComponent(k); });
    cy.on("tap", function (e) { if (e.target === cy) { hideMenu(); $("topo-panel").hidden = true; if (pinned) { pinned = null; clearHighlight(); } } });
    cy.on("cxttap", "node", function (e) { nodeMenu(e.target, e.renderedPosition || e.position); });
    cy.on("cxttap", function (e) { if (e.target === cy) backgroundMenu(e.renderedPosition || e.position); });
    cy.on("pan zoom", hideMenu);
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
          el.appendChild(make("p", "empty", el.dataset.view === "logical"
            ? "No Proxmox data yet. Add the Proxmox API on Targets, or add a Proxmox node as an SSH machine."
            : "Nothing to draw yet. Add a UniFi gateway on Targets."));
          return;
        }
        build(raw);
      })
      .catch(function (err) { el.textContent = "Could not load topology: " + err.message; });
  }

  // ------------------------------------------------------------ wiring
  document.addEventListener("DOMContentLoaded", function () {
    load();
    ["topo-containers", "topo-undocumented", "topo-everything"].forEach(function (id) {
      var c = $(id);
      if (c) c.addEventListener("change", function () { applyFilters(); runLayout(true); });
    });
    var s = $("topo-search");
    if (s) {
      s.addEventListener("input", function () { search(s.value); });
      s.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          var hits = search(s.value);
          if (hits && hits.length) { cy.animate({ fit: { eles: hits, padding: 120 } }, { duration: 450 }); if (hits.length === 1) showPanel(hits[0]); }
        }
        if (e.key === "Escape") { s.value = ""; search(""); }
      });
    }
    document.querySelectorAll("[data-layout]").forEach(function (b) {
      b.addEventListener("click", function () {
        layoutName = b.dataset.layout;
        document.querySelectorAll("[data-layout]").forEach(function (o) { o.classList.toggle("on", o === b); });
        if (cy) runLayout(true);
      });
    });
    var fit = $("topo-fit");
    if (fit) fit.addEventListener("click", function () { if (cy) cy.animate({ fit: { eles: cy.elements(":visible"), padding: 30 } }, { duration: 400 }); });
    var p = $("topo-png");
    if (p) p.addEventListener("click", function () { if (cy) png(); });
    var close = $("topo-panel-close");
    if (close) close.addEventListener("click", function () { $("topo-panel").hidden = true; });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") { hideMenu(); var pnl = $("topo-panel"); if (pnl) pnl.hidden = true; } });
    document.addEventListener("click", function (e) { var m = $("topo-menu"); if (m && !m.hidden && !m.contains(e.target)) hideMenu(); });
    el = $("cy");
    if (el) el.addEventListener("contextmenu", function (e) { e.preventDefault(); });
  });

  window.atlasTopology = {
    redraw: function () { if (raw.length) { iconCache = {}; build(raw); } },
    graph: function () { return cy; }
  };
})();
