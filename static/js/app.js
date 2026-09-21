/* =========================================================================
   app.js -- landing page behaviour
   - submits the scan via fetch() to /api/scan (AJAX, no page reload)
   - renders the scored report card
   - animates the score ring
   - theme toggle + reveal-on-scroll
   - deep-links: /?scan=<id> reopens a saved scan
   ========================================================================= */

(function () {
  "use strict";

  // ---- shared helpers ---------------------------------------------------
  const $ = (sel) => document.querySelector(sel);
  const RING_CIRCUMFERENCE = 2 * Math.PI * 62; // r=62 in the SVG

  const STATUS_ICON = {
    pass: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
    fail: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
    warn: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>',
    info: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16v-4M12 8h.01"/><circle cx="12" cy="12" r="10"/></svg>',
  };

  const CAT_LABEL = { VA: "Assessment", PT: "Pen-test" };

  // score -> ring colour (mirrors CSS status colours)
  function scoreColor(score) {
    if (score >= 80) return getVar("--pass");
    if (score >= 55) return getVar("--warn");
    return getVar("--fail");
  }
  function getVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // ---- report rendering -------------------------------------------------
  function renderReport(report) {
    const summary = report.summary;

    // headline numbers
    $("#reportUrl").textContent = report.url;
    $("#reportRating").textContent = summary.rating + " security posture";
    $("#statPass").textContent = summary.passed;
    $("#statFail").textContent = summary.failed;
    $("#statWarn").textContent = summary.warned;
    $("#statTime").textContent = ((report.duration_ms || 0) / 1000).toFixed(1) + "s";

    // grade pill (colour-coded)
    const gradeEl = $("#reportGrade");
    const col = scoreColor(summary.score);
    gradeEl.textContent = "Grade " + summary.grade;
    gradeEl.style.background = "color-mix(in srgb, " + col + " 15%, transparent)";
    gradeEl.style.color = col;

    // cards
    const cards = $("#cards");
    cards.innerHTML = "";
    report.results.forEach((r, i) => cards.appendChild(buildCard(r, i)));

    // reveal, then animate the ring after layout settles
    $("#report").classList.add("show");
    requestAnimationFrame(() => animateRing(summary.score));
  }

  function buildCard(r, index) {
    const card = document.createElement("div");
    card.className = "card";
    card.style.animationDelay = (index * 60) + "ms";

    const hasEvidence = r.evidence && r.evidence.length;
    const evId = "ev-" + r.id + "-" + index;
    const fixId = "fix-" + r.id + "-" + index;
    // Only offer a fix on findings that need one.
    const showFix = r.remediation && (r.status === "fail" || r.status === "warn");

    const chevron = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';

    card.innerHTML = `
      <div class="card-head">
        <div class="status-dot ${r.status}">${STATUS_ICON[r.status] || STATUS_ICON.info}</div>
        <div class="card-titles">
          <div class="card-name">${escapeHtml(r.name)}</div>
          <div class="card-detail">${escapeHtml(r.detail)}</div>
        </div>
        ${r.owasp ? `<span class="owasp-tag" title="${escapeHtml(r.owasp)}">${escapeHtml(r.owasp.split(":")[0])}</span>` : ""}
        <span class="tag-cat">${CAT_LABEL[r.category] || r.category}</span>
        <span class="badge ${r.status}">${r.status}</span>
      </div>
      <div class="card-actions">
        ${hasEvidence ? `
          <button class="card-toggle evidence-toggle" aria-expanded="false" data-target="${evId}" data-show="Show evidence" data-hide="Hide evidence">
            <span>Show evidence</span>${chevron}
          </button>` : ""}
        ${showFix ? `
          <button class="card-toggle fix-toggle" aria-expanded="false" data-target="${fixId}" data-show="How to fix" data-hide="Hide fix">
            <svg class="wrench" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3 17.8 6.2 21l6.3-6.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.3-2.3 2.6-2.6z"/></svg>
            <span>How to fix</span>${chevron}
          </button>` : ""}
      </div>
      ${hasEvidence ? `
        <div class="evidence" id="${evId}">
          <ul>${r.evidence.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>
        </div>` : ""}
      ${showFix ? buildFixPanel(r.remediation, fixId) : ""}
    `;
    return card;
  }

  function buildFixPanel(rem, fixId) {
    const steps = (rem.steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("");
    return `
      <div class="fix-panel" id="${fixId}">
        <div class="fix-head">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1h6c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/></svg>
          Recommended fix
        </div>
        ${rem.summary ? `<p class="fix-summary">${escapeHtml(rem.summary)}</p>` : ""}
        ${steps ? `<ol class="fix-steps">${steps}</ol>` : ""}
        ${rem.code ? `<pre class="fix-code">${escapeHtml(rem.code)}</pre>` : ""}
      </div>`;
  }

  // one delegated listener for evidence + fix toggles
  function wireEvidenceToggles() {
    $("#cards").addEventListener("click", (e) => {
      const btn = e.target.closest(".card-toggle");
      if (!btn) return;
      const box = document.getElementById(btn.dataset.target);
      if (!box) return;
      const open = box.classList.toggle("show");
      btn.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", String(open));
      const label = btn.querySelector("span");
      if (label) label.textContent = open ? btn.dataset.hide : btn.dataset.show;
    });
  }

  function animateRing(score) {
    const ring = $("#ringFill");
    ring.style.stroke = scoreColor(score);
    ring.style.strokeDasharray = RING_CIRCUMFERENCE;
    ring.style.strokeDashoffset = RING_CIRCUMFERENCE; // start empty
    // force reflow so the transition runs from empty -> value
    void ring.getBoundingClientRect();
    const offset = RING_CIRCUMFERENCE * (1 - score / 100);
    ring.style.strokeDashoffset = offset;

    // count-up the number
    const numEl = $("#scoreNum");
    const start = performance.now();
    const dur = 1400;
    function tick(now) {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      numEl.textContent = Math.round(eased * score);
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // ---- scanning flow ----------------------------------------------------
  const LOADING_STEPS = [
    "Resolving target…",
    "Checking HTTPS, headers, cookies & CORS…",
    "Fingerprinting components for known CVEs…",
    "Probing for exposed config files & IDOR…",
    "Testing every input for XSS & SQL injection…",
    "Running blind SQLi, command injection & SSTI…",
    "Checking path traversal, open redirect & CRLF…",
    "Scoring results…",
  ];
  let loadingTimer = null;

  function startLoading() {
    $("#formError").classList.remove("show");
    $("#report").classList.remove("show");
    $("#loading").classList.add("show");
    $("#scanBtn").disabled = true;
    $("#scanBtn").textContent = "Scanning…";

    let i = 0;
    const stepEl = $("#loadingSteps");
    stepEl.textContent = LOADING_STEPS[0];
    loadingTimer = setInterval(() => {
      i = (i + 1) % LOADING_STEPS.length;
      stepEl.textContent = LOADING_STEPS[i];
    }, 900);
  }

  function stopLoading() {
    clearInterval(loadingTimer);
    $("#loading").classList.remove("show");
    $("#scanBtn").disabled = false;
    $("#scanBtn").textContent = "Scan";
  }

  function showError(msg) {
    const el = $("#formError");
    el.textContent = msg;
    el.classList.add("show");
  }

  // Give up (and tell the user) if a scan runs longer than this.
  const SCAN_TIMEOUT_MS = 120000; // 2 minutes

  async function runScan(url) {
    startLoading();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
      const data = await res.json();
      if (!res.ok || data.ok === false) {
        stopLoading();
        showError(data.error || "Something went wrong while scanning.");
        return;
      }
      stopLoading();
      renderReport(data);
      // update the URL so the report is shareable/refreshable
      history.replaceState(null, "", "/?scan=" + data.id);
      $("#report").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      stopLoading();
      if (err.name === "AbortError") {
        showError("The scan is taking too long and was stopped. The target may be slow or unreachable — try again or use a faster target.");
      } else {
        showError("Could not reach the server. Is the Flask app running?");
      }
    } finally {
      clearTimeout(timer);
    }
  }

  async function loadSavedScan(id) {
    startLoading();
    try {
      const res = await fetch("/api/scan/" + id);
      const data = await res.json();
      stopLoading();
      if (!res.ok || data.ok === false) {
        showError("That saved scan could not be found.");
        return;
      }
      // saved rows store summary fields flat; rebuild the report shape
      const report = {
        url: data.url,
        duration_ms: data.duration_ms,
        results: data.results,
        summary: {
          score: data.score, grade: data.grade, rating: data.rating,
          passed: data.passed, failed: data.failed, warned: data.warned, total: data.total,
        },
      };
      renderReport(report);
      $("#urlInput").value = data.url;
    } catch (err) {
      stopLoading();
    }
  }

  // ---- theme ------------------------------------------------------------
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
      // if a report is showing, recolour the ring for the new theme
      const num = parseInt($("#scoreNum")?.textContent || "0", 10);
      if ($("#report").classList.contains("show")) {
        $("#ringFill").style.stroke = scoreColor(num);
      }
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

  // ---- reveal on scroll -------------------------------------------------
  function initReveal() {
    const els = document.querySelectorAll(".reveal");
    if (!("IntersectionObserver" in window)) {
      els.forEach((e) => e.classList.add("in"));
      return;
    }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
      });
    }, { threshold: 0.15 });
    els.forEach((e) => io.observe(e));
  }

  // ---- boot -------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initReveal();
    wireEvidenceToggles();

    $("#scanForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const url = $("#urlInput").value.trim();
      if (!url) { showError("Please enter a URL to scan."); return; }
      runScan(url);
    });

    document.querySelectorAll(".chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        $("#urlInput").value = chip.dataset.url;
        $("#urlInput").focus();
      });
    });

    // deep link: /?scan=<id>
    const params = new URLSearchParams(location.search);
    const scanId = params.get("scan");
    if (scanId) loadSavedScan(scanId);
  });
})();
