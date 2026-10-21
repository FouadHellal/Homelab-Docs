// atlas UI glue. No inline scripts anywhere (strict CSP); everything starts here.
// Topology lives in topology.js (loaded only on that page).
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

  // ------------------------------------------------------------ list filtering
  // <div class="seg" data-filter-target="#grid"><button data-filter="pve-vm">…  → items' data-kind
  function wireSegFilters(root) {
    root.querySelectorAll(".seg[data-filter-target]").forEach(function (seg) {
      var target = document.querySelector(seg.dataset.filterTarget);
      if (!target) return;
      seg.querySelectorAll("[data-filter]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var kinds = btn.dataset.filter.split(" ");
          seg.querySelectorAll("[data-filter]").forEach(function (b) { b.classList.toggle("on", b === btn); });
          target.querySelectorAll("[data-kind]").forEach(function (item) {
            item.classList.toggle("is-hidden", kinds[0] !== "all" && kinds.indexOf(item.dataset.kind) < 0);
          });
        });
      });
    });
  }

  // <input data-search-target="#table-or-grid">  → hides children whose data-search lacks the text
  function wireSearch(root) {
    root.querySelectorAll("input[data-search-target]").forEach(function (input) {
      input.addEventListener("input", function () {
        var q = input.value.trim().toLowerCase();
        document.querySelectorAll(input.dataset.searchTarget).forEach(function (target) {
          target.querySelectorAll("[data-search]").forEach(function (item) {
            item.classList.toggle("no-match", q !== "" && item.dataset.search.toLowerCase().indexOf(q) < 0);
          });
        });
      });
    });
  }

  // <div data-tabset><button class="tab-btn" data-tab="id">…<div class="tab-panel" id="id">
  function wireTabs(root) {
    root.querySelectorAll("[data-tabset]").forEach(function (set) {
      set.querySelectorAll(".tab-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
          set.querySelectorAll(".tab-btn").forEach(function (b) { b.classList.toggle("on", b === btn); });
          set.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.toggle("on", p.id === btn.dataset.tab); });
          var search = set.querySelector("input[data-search-target]");
          if (search) search.dispatchEvent(new Event("input"));
        });
      });
    });
  }

  // ------------------------------------------------------------ toast + copy buttons
  function toast(msg) {
    var t = document.createElement("div");
    t.className = "toast";
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.classList.add("out"); }, 2400);
    setTimeout(function () { t.remove(); }, 3000);
  }
  window.atlasToast = toast;
  // <button data-copy="text" data-copy-what="SSH command">
  function wireCopy(root) {
    root.querySelectorAll("[data-copy]").forEach(function (b) {
      b.addEventListener("click", function () {
        if (!navigator.clipboard) { toast(b.dataset.copy); return; }
        navigator.clipboard.writeText(b.dataset.copy).then(function () {
          toast((b.dataset.copyWhat || "Text") + " copied");
        });
      });
    });
  }

  // ------------------------------------------------------------ dropdown menus (<details>)
  function wireDropdowns() {
    var menus = Array.prototype.slice.call(document.querySelectorAll("details.dropdown"));
    menus.forEach(function (d) {
      d.addEventListener("toggle", function () {
        if (d.open) menus.forEach(function (o) { if (o !== d) o.open = false; });
      });
    });
    document.addEventListener("click", function (e) {
      menus.forEach(function (d) { if (d.open && !d.contains(e.target)) d.open = false; });
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") menus.forEach(function (d) { if (d.open) { d.open = false; d.querySelector("summary").focus(); } });
    });
  }

  // ------------------------------------------------------------ progress bars (CSP: no style attrs)
  function wireBars(root) {
    root.querySelectorAll("[data-pct]").forEach(function (b) {
      var v = Math.max(0, Math.min(100, parseFloat(b.dataset.pct) || 0));
      b.style.width = v + "%";
      b.classList.toggle("hot", v >= 85);
    });
  }

  // ------------------------------------------------------------ radio pills (Services state)
  function wireRadioPills(root) {
    root.querySelectorAll(".seg-radio").forEach(function (set) {
      set.addEventListener("change", function () {
        set.querySelectorAll("label").forEach(function (l) { l.classList.toggle("on", l.querySelector("input").checked); });
      });
    });
  }

  // ------------------------------------------------------------ quick find (Ctrl+K)
  var paletteItems = null;
  function openPalette() {
    var dlg = document.getElementById("palette");
    if (!dlg || typeof dlg.showModal !== "function") return;
    var input = document.getElementById("palette-q");
    dlg.showModal();
    input.value = "";
    input.focus();
    if (paletteItems) { renderPalette(""); return; }
    fetch("/api/palette", { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : { items: [] }; })
      .then(function (d) { paletteItems = d.items || []; renderPalette(input.value); })
      .catch(function () { paletteItems = []; });
  }
  function score(item, q) {
    var l = item.label.toLowerCase(), h = (item.hint || "").toLowerCase();
    if (!q) return item.hint === "page" ? 1 : 0;
    if (l === q) return 100;
    if (l.indexOf(q) === 0) return 60;
    if (l.indexOf(q) > 0) return 30;
    if (h.indexOf(q) >= 0) return 10;
    // letters in order ("dkr01" -> docker01)
    var i = 0;
    for (var c = 0; c < l.length && i < q.length; c++) if (l[c] === q[i]) i++;
    return i === q.length ? 5 : 0;
  }
  function renderPalette(q) {
    var list = document.getElementById("palette-list");
    if (!list || !paletteItems) return;
    q = q.trim().toLowerCase();
    var hits = paletteItems.map(function (it) { return { it: it, s: score(it, q) }; })
      .filter(function (x) { return x.s > 0; })
      .sort(function (a, b) { return b.s - a.s || a.it.label.localeCompare(b.it.label); })
      .slice(0, 12);
    list.textContent = "";
    hits.forEach(function (x, i) {
      var li = document.createElement("li");
      li.setAttribute("role", "option");
      if (i === 0) li.classList.add("on");
      var a = document.createElement("a");
      a.href = x.it.href;
      a.appendChild(document.createTextNode(x.it.label));
      var hint = document.createElement("span");
      hint.className = "muted small";
      hint.textContent = x.it.hint || "";
      a.appendChild(hint);
      li.appendChild(a);
      list.appendChild(li);
    });
    if (!hits.length) {
      var none = document.createElement("li");
      none.className = "muted";
      none.textContent = "Nothing found";
      list.appendChild(none);
    }
  }
  function movePalette(step) {
    var items = Array.prototype.slice.call(document.querySelectorAll("#palette-list li[role=option]"));
    if (!items.length) return;
    var i = items.findIndex(function (li) { return li.classList.contains("on"); });
    items.forEach(function (li) { li.classList.remove("on"); });
    var next = items[(i + step + items.length) % items.length];
    next.classList.add("on");
    next.scrollIntoView({ block: "nearest" });
  }
  function wirePalette() {
    var btn = document.getElementById("palette-open");
    var input = document.getElementById("palette-q");
    var dlg = document.getElementById("palette");
    if (!dlg || !input) return;
    if (btn) btn.addEventListener("click", openPalette);
    document.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); openPalette(); }
    });
    input.addEventListener("input", function () { renderPalette(input.value); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); movePalette(1); }
      if (e.key === "ArrowUp") { e.preventDefault(); movePalette(-1); }
      if (e.key === "Enter") {
        var on = document.querySelector("#palette-list li.on a");
        if (on) window.location.href = on.getAttribute("href");
      }
    });
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireDropdowns();
    wireBars(document);
    wireRadioPills(document);
    wirePalette();
    wireCopy(document);
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.addEventListener("click", function () {
        var dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        var current = document.documentElement.dataset.theme || (dark ? "dark" : "light");
        var next = current === "dark" ? "light" : "dark";
        applyTheme(next);
        try { localStorage.setItem("atlas-theme", next); } catch (e) { /* private mode */ }
        if (window.atlasTopology) window.atlasTopology.redraw();
      });
    }
    wireSegFilters(document);
    wireSearch(document);
    wireTabs(document);
  });

  // htmx swaps in new rows: re-run the search filter so it stays applied.
  document.addEventListener("htmx:afterSwap", function (e) { wireTabs(e.target); wireBars(e.target); });
})();
