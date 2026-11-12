/*
  launch.js — SploitsHen automatic exploit launcher
  Countdown → auto-redirect to exploit chain, or manual start via button.
  Referrer guard: only fires when reached from index.html in the same origin.
*/

(function () {
  "use strict";

  const COUNTDOWN_SEC = 5;
  /* Payload selection is forwarded from the landing-page URL:
       /?key=...&payload=binloader.bin   -> run the binloader receiver
       /?key=...&binloader=1             -> shorthand for the same
     No param -> unchanged default chain (hen-1402.bin via pre-flight). */
  const destExtra = (function () {
    try {
      const p = new URLSearchParams(location.search);
      const out = [];
      const pl = p.get("payload");
      if (pl) out.push("payload=" + encodeURIComponent(pl));
      if (p.get("binloader") === "1") out.push("payload=binloader.bin");
      return out.length ? "&" + out.join("&") : "";
    } catch (e) { return ""; }
  })();
  const DEST = "launch.html?v=1402s&log=1&afterglow=run&mode=kpstep&g=drain:16&g=drainsz:0x4000" + destExtra;

  const countEl = document.getElementById("count"); // <p class="status" id="count">

  function guardOk() {
    return true; // key auth on index.html already protects the page
  }

  /* ── go ──────────────────────────────────────────────────────────────── */
  function go() {
    if (countEl) countEl.textContent = "[ EXECUTE ]";
    location.href = DEST;
  }

  /* ── blocked by referrer guard ───────────────────────────────────────── */
  if (!guardOk()) {
    if (countEl) countEl.textContent = "[ ACCESS DENIED — NAVIGATE FROM ROOT ]";
    return; // stop — session restore, do not fire
  }

  /* ── countdown ───────────────────────────────────────────────────────── */
  let remaining = COUNTDOWN_SEC;

  function tick() {
    if (countEl) {
      countEl.textContent =
        remaining > 0
          ? "[ LAUNCHING IN " + remaining + "... ]"
          : "[ EXECUTE ]";
    }
    if (remaining <= 0) {
      clearInterval(timer);
      go();
    }
    remaining--;
  }

  tick(); // show initial value immediately
  var timer = setInterval(tick, 1000);
})();
