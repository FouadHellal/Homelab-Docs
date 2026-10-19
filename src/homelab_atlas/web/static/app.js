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

  document.addEventListener("DOMContentLoaded", function () {
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
  document.addEventListener("htmx:afterSwap", function (e) { wireTabs(e.target); });
})();
