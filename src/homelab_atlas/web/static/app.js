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

  // ------------------------------------------------------------ Proxmox board filter (ADR-045)
  function wireBoard(root) {
    var q = root.querySelector("#pb-search"), stopped = root.querySelector("#pb-stopped");
    if (!q || !stopped) return;
    var count = root.querySelector("#pb-count");
    function apply() {
      var needle = q.value.trim().toLowerCase(), shown = 0, all = 0;
      root.querySelectorAll(".pb-guest").forEach(function (g) {
        all += 1;
        var ok = (!needle || (g.dataset.search || "").indexOf(needle) >= 0) &&
          (stopped.checked || g.dataset.status !== "stopped");
        g.hidden = !ok;
        if (ok) shown += 1;
      });
      if (count) count.textContent = shown === all ? all + " machines" : shown + " of " + all;
    }
    q.addEventListener("input", apply);
    stopped.addEventListener("change", apply);
    apply();
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
    document.querySelectorAll(".js-palette").forEach(function (b) { b.addEventListener("click", function () { closeSide(); openPalette(); }); });
    if (btn && !btn.classList.contains("js-palette")) btn.addEventListener("click", openPalette);
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

  // ------------------------------------------------------------ sidebar drawer (phones, tablets)
  function closeSide() {
    document.body.classList.remove("side-open");
    var scrim = document.getElementById("scrim"), open = document.getElementById("side-open");
    if (scrim) scrim.hidden = true;
    if (open) open.setAttribute("aria-expanded", "false");
  }
  function wireSide() {
    var open = document.getElementById("side-open"), close = document.getElementById("side-close");
    var scrim = document.getElementById("scrim");
    if (!open) return;
    open.addEventListener("click", function () {
      document.body.classList.add("side-open");
      if (scrim) scrim.hidden = false;
      open.setAttribute("aria-expanded", "true");
      var here = document.querySelector(".side-nav [aria-current]") || document.querySelector(".side-nav a");
      if (here) here.focus();
    });
    if (close) close.addEventListener("click", closeSide);
    if (scrim) scrim.addEventListener("click", closeSide);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeSide(); });
  }

  // ------------------------------------------------------------ wide tables scroll inside their card
  function wrapTables(root) {
    root.querySelectorAll("table").forEach(function (t) {
      var p = t.parentElement;
      if (!p || p.classList.contains("table-scroll") || p.classList.contains("tscroll") || p.closest(".tab-panel")) return;
      var w = document.createElement("div");
      w.className = "tscroll";
      p.insertBefore(w, t);
      w.appendChild(t);
    });
  }

  // ------------------------------------------------------------ facet filters + sortable tables
  // <div data-facets="#table"><button data-facet="state" data-value="healthy">  → rows' data-state
  function wireFacets(root) {
    root.querySelectorAll("[data-facets]").forEach(function (box) {
      var table = document.querySelector(box.dataset.facets);
      if (!table) return;
      var active = {};
      function apply() {
        table.querySelectorAll("tbody tr").forEach(function (tr) {
          var ok = Object.keys(active).every(function (k) { return !active[k] || tr.dataset[k] === active[k]; });
          tr.classList.toggle("is-hidden", !ok);
        });
      }
      box.querySelectorAll("[data-facet]").forEach(function (btn) {
        btn.setAttribute("aria-pressed", btn.classList.contains("on") ? "true" : "false");
        btn.addEventListener("click", function () {
          var f = btn.dataset.facet;
          active[f] = btn.dataset.value;
          box.querySelectorAll("[data-facet='" + f + "']").forEach(function (b) {
            b.classList.toggle("on", b === btn);
            b.setAttribute("aria-pressed", b === btn ? "true" : "false");
          });
          apply();
        });
      });
    });
  }
  function wireSort(root) {
    root.querySelectorAll("table.sortable").forEach(function (table) {
      table.querySelectorAll("th[data-sort]").forEach(function (th, col) {
        th.tabIndex = 0;
        th.setAttribute("role", "button");
        function sort() {
          var asc = th.getAttribute("aria-sort") !== "ascending";
          table.querySelectorAll("th[data-sort]").forEach(function (o) { o.removeAttribute("aria-sort"); });
          th.setAttribute("aria-sort", asc ? "ascending" : "descending");
          var body = table.tBodies[0];
          var rows = Array.prototype.slice.call(body.rows);
          var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
          function key(r) {
            var c = r.cells[idx];
            if (!c) return "";
            var v = c.dataset.sortValue;
            return v !== undefined ? parseFloat(v) : c.textContent.trim().toLowerCase();
          }
          rows.sort(function (a, b) {
            var x = key(a), y = key(b);
            var r = (typeof x === "number" && typeof y === "number") ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
            return asc ? r : -r;
          });
          rows.forEach(function (r) { body.appendChild(r); });
        }
        th.addEventListener("click", sort);
        th.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } });
      });
    });
  }


  // ------------------------------------------------------------ portal (ADR-049)
  // Search, category filter, clock and keyboard shortcuts. The page works without this:
  // every shortcut is a plain link and every category is visible.
  function wirePortal() {
    var root = document.querySelector("[data-portal]");
    if (!root) return;
    var time = document.getElementById("p-time"), date = document.getElementById("p-date");
    function tick() {
      var now = new Date();
      if (time) { time.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); time.dateTime = now.toISOString(); }
      if (date) date.textContent = now.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
    }
    tick();
    setInterval(tick, 15000);

    var q = document.getElementById("p-q");
    var chips = Array.prototype.slice.call(root.querySelectorAll(".p-chip"));
    var groups = Array.prototype.slice.call(root.querySelectorAll("[data-group]"));
    var empty = document.getElementById("p-empty"), emptyQ = document.getElementById("p-empty-q");
    var show = "all";
    try { show = sessionStorage.getItem("atlas-portal-show") || "all"; } catch (e) { /* storage off */ }
    if (!chips.some(function (c) { return c.dataset.show === show; })) show = "all";

    function apply() {
      var text = q ? q.value.trim().toLowerCase() : "";
      var any = false;
      chips.forEach(function (c) { c.setAttribute("aria-pressed", c.dataset.show === show ? "true" : "false"); });
      groups.forEach(function (g) {
        var key = g.dataset.group;
        // While searching, look everywhere except the favorites strip (no duplicate hits).
        var inScope = text ? key !== "fav" : (show === "all" || show === key);
        var hits = 0;
        g.querySelectorAll("li[data-search]").forEach(function (li) {
          var ok = inScope && (!text || li.dataset.search.indexOf(text) >= 0);
          li.hidden = !ok;
          if (ok) hits++;
        });
        g.hidden = hits === 0;
        if (hits) any = true;
      });
      if (empty) {
        empty.hidden = any || !text;
        if (emptyQ) emptyQ.textContent = "“" + (q ? q.value.trim() : "") + "”";
      }
    }
    chips.forEach(function (c) {
      c.addEventListener("click", function () {
        show = c.dataset.show;
        try { sessionStorage.setItem("atlas-portal-show", show); } catch (e) { /* storage off */ }
        if (q && q.value) q.value = "";
        apply();
      });
    });
    if (q) {
      q.addEventListener("input", apply);
      q.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && q.value) { e.preventDefault(); q.value = ""; apply(); }
        if (e.key === "Enter") {
          var first = root.querySelector(".p-groups li[data-search]:not([hidden]) a");
          if (first) { e.preventDefault(); window.open(first.href, "_blank", "noopener,noreferrer"); }
        }
        if (e.key === "ArrowDown") {
          var link = root.querySelector(".p-groups li[data-search]:not([hidden]) a");
          if (link) { e.preventDefault(); link.focus(); }
        }
      });
    }
    var clear = document.getElementById("p-clear");
    if (clear && q) clear.addEventListener("click", function () { q.value = ""; apply(); q.focus(); });
    document.addEventListener("keydown", function (e) {
      if (!q || e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
      var el = document.activeElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) return;
      e.preventDefault();
      q.focus();
      q.select();
    });
    apply();
  }

  document.addEventListener("DOMContentLoaded", function () {
    wirePortal();
    wireFacets(document);
    wireSort(document);
    wireSide();
    wrapTables(document);
    wireDropdowns();
    wireBars(document);
    wireBoard(document);
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
  document.addEventListener("htmx:afterSwap", function (e) { wireTabs(e.target); wireBars(e.target); wrapTables(e.target); });
})();
