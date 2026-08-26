/* ==========================================================================
   NEVINTEL — client behaviour

   Every feature here is PROGRESSIVE. With JavaScript off or broken:
     - all stories stay visible (nothing is hidden by default in CSS)
     - every headline is still a working link to the publisher
     - the explainer panel shows its static fallback text
     - the theme still resolves from the OS preference
   Nothing on this page requires script to read the news.

   No dependencies, no CDN. The 2024 Polyfill.io compromise reached 100,000+
   sites whose only mistake was a script tag pointing at someone else's host.
   ========================================================================== */
(function () {
  "use strict";

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* ---------------------------------------------------------------- theme */
  (function theme() {
    var btn = $("#theme-btn");
    if (!btn) return;

    function resolved() {
      var set = document.documentElement.getAttribute("data-theme");
      if (set) return set;
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light" : "dark";
    }

    function paint() {
      var now = resolved();
      $$("[data-icon]", btn).forEach(function (el) {
        el.hidden = el.getAttribute("data-icon") !== now;
      });
      btn.setAttribute("aria-label",
        now === "dark" ? "Switch to light theme" : "Switch to dark theme");
    }

    btn.addEventListener("click", function () {
      var next = resolved() === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      // Storage throws in private windows and where site data is blocked.
      // The toggle must still work when it does.
      try { localStorage.setItem("nevintel-theme", next); } catch (e) {}
      paint();
    });

    paint();
  })();

  /* ------------------------------------------------------------ relative time */
  (function ago() {
    var MIN = 60000, HOUR = 3600000, DAY = 86400000;
    $$("[data-ago]").forEach(function (el) {
      var t = Date.parse(el.getAttribute("data-ago"));
      if (isNaN(t)) return;
      var d = Date.now() - t;
      if (d < 0) d = 0;
      var out;
      if (d < HOUR) out = Math.max(1, Math.round(d / MIN)) + "m ago";
      else if (d < DAY) out = Math.round(d / HOUR) + "h ago";
      else if (d < DAY * 7) out = Math.round(d / DAY) + "d ago";
      else return; // older than a week: the absolute date is more useful
      el.textContent = out;
    });
  })();

  /* -------------------------------------------------------------- filters */
  (function filters() {
    var feed = $("#feed");
    if (!feed) return;

    var items = $$(".item", feed);
    var countEl = $("#filter-count");
    var clearEl = $("#filter-clear");

    // Several chips of the same kind widen the result (OR); different kinds
    // narrow it (AND). That is what people expect from faceted filtering.
    var state = { topic: [], source: [], cve: [], age: null, hascve: false };

    function toggle(list, value) {
      var i = list.indexOf(value);
      if (i === -1) list.push(value); else list.splice(i, 1);
      return list;
    }

    function tokens(el, attr) {
      var raw = (el.getAttribute(attr) || "").trim();
      return raw ? raw.split(/\s+/) : [];
    }

    function anyIn(have, want) {
      for (var i = 0; i < want.length; i++) {
        if (have.indexOf(want[i]) !== -1) return true;
      }
      return false;
    }

    function apply() {
      var cutoff = state.age ? Date.now() - state.age * 3600000 : null;
      var shown = 0;

      items.forEach(function (li) {
        var ok = true;

        if (ok && state.topic.length) ok = anyIn(tokens(li, "data-topics"), state.topic);
        if (ok && state.source.length) ok = state.source.indexOf(li.getAttribute("data-source")) !== -1;
        if (ok && state.cve.length) ok = anyIn(tokens(li, "data-cves"), state.cve);
        if (ok && state.hascve) ok = tokens(li, "data-cves").length > 0;
        if (ok && cutoff !== null) {
          var t = Date.parse(li.getAttribute("data-date"));
          ok = !isNaN(t) && t >= cutoff;
        }

        li.hidden = !ok;
        if (ok) shown++;
      });

      var active = state.topic.length + state.source.length + state.cve.length +
                   (state.age ? 1 : 0) + (state.hascve ? 1 : 0);

      if (countEl) {
        // Built with DOM nodes rather than innerHTML. These values are
        // integers we derived ourselves, so a string would be safe here --
        // but a site about security should not ship an innerHTML sink at
        // all, because the next edit is where one stops being safe.
        countEl.textContent = "Showing ";
        var strong = document.createElement("b");
        strong.textContent = active ? String(shown) : "all";
        countEl.appendChild(strong);
        countEl.appendChild(document.createTextNode(
          active ? " of " + items.length + " stories" : " " + items.length + " stories"));
      }
      if (clearEl) clearEl.hidden = active === 0;
    }

    function bind(attr, handler) {
      $$("[" + attr + "]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          handler(btn.getAttribute(attr), btn);
          // Keep every chip for the same value in sync across the page --
          // trending topics in the rail and the filter deck at the bottom
          // control the same state.
          syncPressed();
          apply();
          var latest = $("#latest");
          if (latest && !isInView(latest)) {
            latest.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        });
      });
    }

    function isInView(el) {
      var r = el.getBoundingClientRect();
      return r.top < window.innerHeight && r.bottom > 0;
    }

    function syncPressed() {
      $$("[data-filter-topic]").forEach(function (b) {
        b.setAttribute("aria-pressed",
          state.topic.indexOf(b.getAttribute("data-filter-topic")) !== -1);
      });
      $$("[data-filter-source]").forEach(function (b) {
        b.setAttribute("aria-pressed",
          state.source.indexOf(b.getAttribute("data-filter-source")) !== -1);
      });
      $$("[data-filter-cve]").forEach(function (b) {
        b.setAttribute("aria-pressed",
          state.cve.indexOf(b.getAttribute("data-filter-cve")) !== -1);
      });
      $$("[data-filter-age]").forEach(function (b) {
        b.setAttribute("aria-pressed", String(state.age) === b.getAttribute("data-filter-age"));
      });
      $$("[data-filter-hascve]").forEach(function (b) {
        b.setAttribute("aria-pressed", state.hascve);
      });
    }

    bind("data-filter-topic", function (v) { toggle(state.topic, v); });
    bind("data-filter-source", function (v) { toggle(state.source, v); });
    bind("data-filter-cve", function (v) { toggle(state.cve, v); });
    bind("data-filter-age", function (v) {
      var n = parseInt(v, 10);
      state.age = state.age === n ? null : n;
    });
    bind("data-filter-hascve", function () { state.hascve = !state.hascve; });

    if (clearEl) {
      clearEl.addEventListener("click", function () {
        state = { topic: [], source: [], cve: [], age: null, hascve: false };
        syncPressed();
        apply();
      });
    }

    apply();
  })();

  /* ------------------------------------------------------------ explainer */
  (function explainer() {
    var body = $("#explain-body");
    var empty = $("#explain-empty");
    if (!body) return;

    var TOPIC_RULE = "Tags come from published keyword rules in " +
      "pipeline/enrich.py — a headline match scores higher than a snippet " +
      "match, and a topic needs converging signals rather than one stray word.";

    function fill(li) {
      var titleEl = $(".item-title a", li) || $("h1 a", li);
      var tile = $(".tile", li);
      var source = $(".meta", li);
      var link = titleEl ? titleEl.getAttribute("href") : "";
      var date = li.getAttribute("data-date") || "";
      var topics = (li.getAttribute("data-topics") || "").trim();
      var cves = (li.getAttribute("data-cves") || "").trim();

      $("#ex-title").textContent = titleEl ? titleEl.textContent.trim() : "";

      var exTile = $("#ex-tile");
      if (tile && exTile) {
        exTile.textContent = tile.textContent.trim();
        exTile.setAttribute("style", tile.getAttribute("style") || "--h:190");
      }

      $("#ex-source").textContent = source ? source.textContent.trim() : "—";

      var d = Date.parse(date);
      $("#ex-date").textContent = isNaN(d)
        ? "—"
        : new Date(d).toISOString().replace("T", " ").replace(".000Z", " UTC");

      var linkCell = $("#ex-link");
      linkCell.textContent = "";
      if (link) {
        var a = document.createElement("a");
        a.href = link;
        a.rel = "noopener noreferrer nofollow external";
        a.textContent = link;
        linkCell.appendChild(a);
      } else {
        linkCell.textContent = "—";
      }

      var bits = [];
      if (topics) bits.push("Topics: " + topics.split(/\s+/).join(", "));
      if (cves) bits.push("CVEs found in the text: " + cves.split(/\s+/).join(", "));
      $("#ex-rule").textContent = bits.length
        ? bits.join(". ") + ". " + TOPIC_RULE
        : "No topic matched confidently enough to tag. " + TOPIC_RULE;

      var tags = $("#ex-tags");
      tags.textContent = "";
      (cves ? cves.split(/\s+/) : []).forEach(function (c) {
        var s = document.createElement("span");
        s.className = "badge cve";
        s.textContent = c;
        tags.appendChild(s);
      });
      (topics ? topics.split(/\s+/) : []).forEach(function (t) {
        var s = document.createElement("span");
        s.className = "chip";
        s.textContent = t;
        tags.appendChild(s);
      });

      body.classList.add("on");
      if (empty) empty.hidden = true;
    }

    $$("[data-explain]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var host = btn.closest(".item") || btn.closest(".lead");
        if (!host) return;

        var open = btn.getAttribute("aria-expanded") === "true";
        $$("[data-explain]").forEach(function (b) { b.setAttribute("aria-expanded", "false"); });

        if (open) {
          body.classList.remove("on");
          if (empty) empty.hidden = false;
          return;
        }

        btn.setAttribute("aria-expanded", "true");

        // The lead article carries its data on the button, not the <li>.
        if (!host.getAttribute("data-date")) {
          var lead = document.createElement("div");
          lead.setAttribute("data-date", "");
          fill(host);
        } else {
          fill(host);
        }

        $("#explain").scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  })();

  /* ------------------------------------------------- lead decorative art */
  (function art() {
    var canvas = $("#lead-art");
    if (!canvas || !canvas.getContext) return;
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    var ctx = canvas.getContext("2d");
    var nodes = [];
    var raf = null;

    function size() {
      var r = canvas.parentNode.getBoundingClientRect();
      var dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(1, Math.floor(r.width * dpr));
      canvas.height = Math.max(1, Math.floor(r.height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      return r;
    }

    function seed(r) {
      nodes = [];
      var n = Math.max(14, Math.min(40, Math.round(r.width * r.height / 5200)));
      for (var i = 0; i < n; i++) {
        nodes.push({
          x: Math.random() * r.width,
          y: Math.random() * r.height,
          vx: (Math.random() - 0.5) * 0.16,
          vy: (Math.random() - 0.5) * 0.16
        });
      }
    }

    function draw(r) {
      ctx.clearRect(0, 0, r.width, r.height);

      for (var i = 0; i < nodes.length; i++) {
        var a = nodes[i];
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > r.width) a.vx *= -1;
        if (a.y < 0 || a.y > r.height) a.vy *= -1;

        for (var j = i + 1; j < nodes.length; j++) {
          var b = nodes[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 96) {
            ctx.strokeStyle = "rgba(47,216,232," + (0.2 * (1 - dist / 96)).toFixed(3) + ")";
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }

        ctx.fillStyle = i % 5 === 0 ? "rgba(43,224,138,.75)" : "rgba(47,216,232,.45)";
        ctx.beginPath();
        ctx.arc(a.x, a.y, i % 5 === 0 ? 2 : 1.4, 0, Math.PI * 2);
        ctx.fill();
      }

      raf = requestAnimationFrame(function () { draw(r); });
    }

    function start() {
      if (raf) cancelAnimationFrame(raf);
      var r = size();
      if (r.width < 40 || r.height < 40) return;
      seed(r);
      draw(r);
    }

    start();

    var t = null;
    window.addEventListener("resize", function () {
      clearTimeout(t);
      t = setTimeout(start, 180);
    });

    // Stop burning frames when the tab is hidden.
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        if (raf) { cancelAnimationFrame(raf); raf = null; }
      } else if (!raf) {
        start();
      }
    });
  })();

  /* --------------------------------------------------------------- search */
  window.addEventListener("load", function () {
    if (typeof PagefindUI === "undefined") return;
    var el = $("#search");
    if (!el) return;
    new PagefindUI({
      element: "#search",
      showImages: false,
      showSubResults: false,
      excerptLength: 20,
      pageSize: 8,
      resetStyles: false,
      placeholder: "Search intelligence…"
    });
  });

})();
