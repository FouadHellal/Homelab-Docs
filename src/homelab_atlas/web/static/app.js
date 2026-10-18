// atlas UI glue. No inline scripts anywhere (strict CSP); everything starts here.
(function () {
  "use strict";

  // ------------------------------------------------------------ theme toggle
  function storedTheme() {
    try { return localStorage.getItem("atlas-theme"); } catch (e) { return null; }
  }
  function applyTheme(t) {
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  }
  applyTheme(storedTheme());

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.addEventListener("click", function () {
        var dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        var current = document.documentElement.dataset.theme || (dark ? "dark" : "light");
        var next = current === "dark" ? "light" : "dark";
        applyTheme(next);
        try { localStorage.setItem("atlas-theme", next); } catch (e) { /* private mode */ }
        drawTopology();
      });
    }
    drawTopology();
  });

  // ------------------------------------------------------------ topology
  var cyInstance = null;

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  var SHAPES = {
    "unifi-site": "round-rectangle", gateway: "diamond", switch: "rectangle", ap: "ellipse",
    "pve-cluster": "round-rectangle", "pve-node": "rectangle", "pve-vm": "round-rectangle",
    "pve-lxc": "round-rectangle", "linux-host": "round-rectangle", "compose-project": "hexagon",
    container: "ellipse", nas: "barrel", "unknown-device": "triangle", vlan: "round-rectangle"
  };

  // One box per VLAN, members in a square-ish grid: readable and stable between reloads.
  function vlanPositions(elements) {
    var groups = {};
    elements.forEach(function (e) {
      var p = e.data.parent;
      if (p) (groups[p] = groups[p] || []).push(e.data.id);
    });
    var pos = {}, x0 = 0;
    Object.keys(groups).sort().forEach(function (g) {
      var ids = groups[g], cols = Math.max(1, Math.ceil(Math.sqrt(ids.length)));
      ids.forEach(function (id, i) { pos[id] = { x: x0 + (i % cols) * 120, y: Math.floor(i / cols) * 80 }; });
      x0 += cols * 120 + 140;
    });
    return function (node) { return pos[node.id()]; };
  }

  function drawTopology() {
    var el = document.getElementById("cy");
    if (!el || typeof window.cytoscape !== "function") return;
    var view = el.dataset.view;
    fetch(el.dataset.src, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        if (cyInstance) cyInstance.destroy();
        cyInstance = window.cytoscape({
          container: el,
          elements: data.elements,
          style: [
            { selector: "node", style: {
                "label": "data(label)", "font-size": 10, "color": css("--fg"), "text-wrap": "wrap",
                "text-valign": "bottom", "text-margin-y": 4, "background-color": css("--accent"),
                "shape": function (n) { return SHAPES[n.data("kind")] || "ellipse"; },
                "width": 22, "height": 22, "min-zoomed-font-size": 7 } },
            { selector: "node[status = 'unknown'], node[kind = 'unknown-device']", style: { "background-color": css("--bad") } },
            { selector: "node[status = 'missing'], node[status = 'gone']", style: { "background-color": css("--warn") } },
            { selector: "node[kind = 'container']", style: { "width": 12, "height": 12, "background-color": css("--ok") } },
            { selector: ":parent", style: {
                "background-opacity": 0.08, "background-color": css("--accent"), "border-color": css("--muted"),
                "border-width": 1, "padding": 12, "text-valign": "top", "font-weight": "bold", "shape": "round-rectangle" } },
            { selector: "edge", style: {
                "width": 1.2, "line-color": css("--line"), "curve-style": "bezier",
                "target-arrow-shape": "none" } },
            { selector: "edge[kind = 'wireless']", style: { "line-style": "dashed" } }
          ],
          layout: view === "vlan"
            ? { name: "preset", positions: vlanPositions(data.elements), fit: true, padding: 30 }
            : { name: "breadthfirst", directed: true, spacingFactor: 1.1, padding: 20, animate: false }
        });
        cyInstance.on("tap", "node", function (evt) {
          var key = evt.target.data("key");
          if (key) window.location.href = "/entity?key=" + encodeURIComponent(key);
        });
      })
      .catch(function (err) { el.textContent = "Could not load topology: " + err.message; });
  }
})();
