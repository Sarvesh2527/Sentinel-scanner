/* =========================================================================
   history.js -- scan history page
   - lists past scans from /api/history
   - each row opens the saved report at /?scan=<id>
   - delete a single scan, or clear all
   - shares the theme toggle behaviour with the landing page
   ========================================================================= */

(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);

  function scoreColor(score) {
    const root = getComputedStyle(document.documentElement);
    if (score >= 80) return root.getPropertyValue("--pass").trim();
    if (score >= 55) return root.getPropertyValue("--warn").trim();
    return root.getPropertyValue("--fail").trim();
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // "3 minutes ago", "2 days ago", etc.
  function timeAgo(iso) {
    const then = new Date(iso).getTime();
    if (isNaN(then)) return "";
    const secs = Math.floor((Date.now() - then) / 1000);
    const units = [
      ["year", 31536000], ["month", 2592000], ["day", 86400],
      ["hour", 3600], ["minute", 60],
    ];
    for (const [name, s] of units) {
      const v = Math.floor(secs / s);
      if (v >= 1) return v + " " + name + (v > 1 ? "s" : "") + " ago";
    }
    return "just now";
  }

  const CIRC = 2 * Math.PI * 24; // mini ring r=24

  function buildRow(scan, index) {
    const row = document.createElement("div");
    row.className = "history-row";
    row.style.animationDelay = (index * 40) + "ms";
    row.dataset.id = scan.id;

    const col = scoreColor(scan.score);
    const offset = CIRC * (1 - scan.score / 100);

    row.innerHTML = `
      <div class="mini-ring">
        <svg width="54" height="54" viewBox="0 0 54 54">
          <circle cx="27" cy="27" r="24" fill="none" stroke="var(--ring-track)" stroke-width="5"/>
          <circle cx="27" cy="27" r="24" fill="none" stroke="${col}" stroke-width="5"
                  stroke-linecap="round" stroke-dasharray="${CIRC}" stroke-dashoffset="${offset}"/>
        </svg>
        <div class="mini-score">${scan.score}</div>
      </div>
      <div class="history-info">
        <div class="history-url">${escapeHtml(scan.url)}</div>
        <div class="history-time">${timeAgo(scan.created_at)} · Grade ${escapeHtml(scan.grade)} · ${escapeHtml(scan.rating)}</div>
        <div class="history-badges">
          <span class="pill pass">${scan.passed} passed</span>
          ${scan.failed ? `<span class="pill fail">${scan.failed} failed</span>` : ""}
          ${scan.warned ? `<span class="pill warn">${scan.warned} warnings</span>` : ""}
        </div>
      </div>
      <button class="history-del" title="Delete scan" aria-label="Delete scan">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
        </svg>
      </button>
    `;

    // open the saved report
    row.addEventListener("click", (e) => {
      if (e.target.closest(".history-del")) return;
      window.location = "/?scan=" + scan.id;
    });

    // delete this scan
    row.querySelector(".history-del").addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm("Delete this scan from history?")) return;
      const res = await fetch("/api/scan/" + scan.id, { method: "DELETE" });
      if (res.ok) {
        row.style.transition = "opacity .3s, transform .3s";
        row.style.opacity = "0";
        row.style.transform = "scale(.96)";
        setTimeout(load, 300);
      }
    });

    return row;
  }

  async function load() {
    const list = $("#historyList");
    try {
      const res = await fetch("/api/history");
      const data = await res.json();
      const scans = data.scans || [];
      const maxHistory = data.max_history || 3;
      const keepNote = ` · keeping the ${maxHistory} most recent`;

      list.innerHTML = "";
      if (!scans.length) {
        $("#emptyState").style.display = "block";
        $("#clearBtn").style.display = "none";
        $("#historyCount").textContent =
          "No scans recorded yet — history keeps your " + maxHistory + " most recent scans.";
        return;
      }
      $("#emptyState").style.display = "none";
      $("#clearBtn").style.display = "inline-block";
      $("#historyCount").textContent =
        scans.length + (scans.length === 1 ? " scan" : " scans") + " recorded" + keepNote;
      scans.forEach((s, i) => list.appendChild(buildRow(s, i)));
    } catch (err) {
      $("#historyCount").textContent = "Could not load history — is the server running?";
    }
  }

  function initTheme() {
    const saved = localStorage.getItem("theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
    updateThemeIcon();
    $("#themeToggle").addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme");
      const isDark = cur === "dark" ||
        (!cur && window.matchMedia("(prefers-color-scheme: dark)").matches);
      const next = isDark ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("theme", next);
      updateThemeIcon();
      load(); // re-render rings in the new theme's colours
    });
  }
  function updateThemeIcon() {
    const cur = document.documentElement.getAttribute("data-theme");
    const isDark = cur === "dark" ||
      (!cur && window.matchMedia("(prefers-color-scheme: dark)").matches);
    const icon = $("#themeIcon");
    if (!icon) return;
    icon.innerHTML = isDark
      ? '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/>'
      : '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"/>';
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    load();
    $("#clearBtn").addEventListener("click", async () => {
      if (!confirm("Clear the entire scan history? This cannot be undone.")) return;
      const res = await fetch("/api/history", { method: "DELETE" });
      if (res.ok) load();
    });
  });
})();
