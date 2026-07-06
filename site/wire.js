/* wire.js - binds snapshot.json to the static page. Vanilla JS, no libraries.
 *
 * Usage: give any element a data-bind="dot.path" attribute (a path into the
 * snapshot, e.g. data-bind="trust_band.anchors_arc") and optionally a
 * data-format attribute:
 *   int        1234567    -> "1,234,567"
 *   money      1240.5     -> "$1,241"        (sign kept for negatives)
 *   ago        ISO ts     -> "6 MIN AGO"     (re-ticks every 60 s)
 *   age-days   ISO ts     -> "DAY 13"        (re-ticks every 60 s)
 *   age-clock  ISO ts     -> "00:14:32"      (elapsed, re-ticks every 1 s)
 * A missing/null value renders as an em dash. Elements WITHOUT data-bind are
 * never touched. An element with [data-feed-list] gets one row per feed item
 * ("<time> <kind> · <text>", newest at top, max 50).
 *
 * Body state classes: .state-offline while the last fetch failed (previous
 * values are kept on screen), .state-stale when the snapshot itself is older
 * than 75 minutes. Elements bound to a chain_integrity path get .state-fail
 * when the value is "FAIL".
 *
 * WebGL bridge: after every SUCCESSFUL fetch the full snapshot is exposed as
 * `window.ACOS_DATA` and announced via
 * `document.dispatchEvent(new CustomEvent('acos:data', {detail: snapshot}))`,
 * so a canvas/WebGL layer can consume the same data without touching the DOM
 * bindings. On a failed fetch the last ACOS_DATA is KEPT (never cleared) -
 * consumers keep stale-but-real data plus the body's .state-offline flag.
 */
(function () {
  "use strict";

  var SNAPSHOT_URL = "snapshot.json";
  var REFRESH_MS = 5 * 60 * 1000;   // re-fetch every 5 minutes
  var STALE_MS = 75 * 60 * 1000;    // snapshot older than this -> state-stale
  var MISSING = "—";           // em dash for absent values
  var FEED_MAX = 50;

  var snapshot = null;
  var generatedAtMs = null;

  function get(obj, path) {
    var parts = path.split(".");
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      if (cur === null || cur === undefined) return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  function thousands(n) {
    return Math.round(n).toLocaleString("en-US");
  }

  function fmtInt(v) {
    var n = Number(v);
    return isFinite(n) ? thousands(n) : MISSING;
  }

  function fmtMoney(v) {
    var n = Number(v);
    if (!isFinite(n)) return MISSING;
    var sign = n < 0 ? "-" : "";
    return sign + "$" + thousands(Math.abs(n));
  }

  function fmtAgo(v, nowMs) {
    var t = Date.parse(v);
    if (isNaN(t)) return MISSING;
    var s = Math.max(0, Math.floor((nowMs - t) / 1000));
    if (s < 60) return "JUST NOW";
    var m = Math.floor(s / 60);
    if (m < 60) return m + " MIN AGO";
    var h = Math.floor(m / 60);
    if (h < 24) return h + " H AGO";
    return Math.floor(h / 24) + " D AGO";
  }

  function fmtAgeDays(v, nowMs) {
    // age = full elapsed days (9d16h -> "DAY 9"), no ordinal +1
    var t = Date.parse(v);
    if (isNaN(t)) return MISSING;
    var d = Math.max(0, Math.floor((nowMs - t) / 86400000));
    return "DAY " + d;
  }

  function pad2(n) {
    return (n < 10 ? "0" : "") + n;
  }

  function fmtAgeClock(v, nowMs) {
    var t = Date.parse(v);
    if (isNaN(t)) return MISSING;
    var s = Math.max(0, Math.floor((nowMs - t) / 1000));
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    return pad2(h) + ":" + pad2(m) + ":" + pad2(s % 60);
  }

  function formatValue(value, format, nowMs) {
    if (value === null || value === undefined) return MISSING;
    switch (format) {
      case "int": return fmtInt(value);
      case "money": return fmtMoney(value);
      case "ago": return fmtAgo(value, nowMs);
      case "age-days": return fmtAgeDays(value, nowMs);
      case "age-clock": return fmtAgeClock(value, nowMs);
      default: return String(value);
    }
  }

  // ticking=true re-renders only the time-derived formats (ago / age-days /
  // age-clock) so a ticker never rewrites static text.
  function applyBindings(ticking, onlyClock) {
    if (!snapshot) return;
    var nowMs = Date.now();
    var els = document.querySelectorAll("[data-bind]");
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var format = el.getAttribute("data-format") || "";
      if (ticking) {
        if (onlyClock && format !== "age-clock") continue;
        if (!onlyClock && format !== "ago" && format !== "age-days") continue;
      }
      var path = el.getAttribute("data-bind");
      var value = get(snapshot, path);
      el.textContent = formatValue(value, format, nowMs);
      if (path.indexOf("chain_integrity") !== -1) {
        el.classList.toggle("state-fail", value === "FAIL");
      }
    }
  }

  function renderFeed() {
    var host = document.querySelector("[data-feed-list]");
    if (!host || !snapshot) return;
    var feed = snapshot.feed;
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!feed || !feed.length) return;
    var n = Math.min(feed.length, FEED_MAX);
    for (var i = 0; i < n; i++) {  // snapshot feed is newest-first already
      var item = feed[i] || {};
      var ts = String(item.ts || "");
      var when = ts.length >= 16 ? ts.slice(5, 16).replace("T", " ") : ts;
      var row = document.createElement("div");
      row.className = "feed-row";
      row.textContent = when + " " + (item.kind || "") + " · " + (item.text || "");
      host.appendChild(row);
    }
  }

  function updateStale() {
    if (generatedAtMs === null) return;
    document.body.classList.toggle(
      "state-stale", Date.now() - generatedAtMs > STALE_MS
    );
  }

  // --- canvas adapter -------------------------------------------------------
  // The WebGL layer (RELEASE-MANIFEST §3/§5) consumes a few derived paths that
  // the emitter does not produce. All additions are ADDITIVE and derived from
  // real snapshot fields - nothing is invented.
  function hhmm(ts) {
    var s = String(ts || "");
    return s.length >= 16 ? s.slice(11, 16) : "";
  }

  var MON = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];

  function fmtSiteTs(ms) {
    var d = new Date(ms);
    return pad2(d.getUTCDate()) + " " + MON[d.getUTCMonth()] + ", " +
           pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes()) + " UTC";
  }

  function enrichForCanvas(data) {
    var tb = data.trust_band || {};
    // next anchor: anchoring is decision-driven (a new journal entry mints an
    // anchor within the hour). Future ETA -> site-format time; already passed
    // (quiet market, no new decisions) -> the honest label.
    if (tb.last_anchor_ts && !tb.next_anchor_eta) {
      var t = Date.parse(tb.last_anchor_ts);
      if (!isNaN(t)) {
        var eta = t + 3600000;
        tb.next_anchor_eta = eta > Date.now() ? fmtSiteTs(eta) : "ON NEXT DECISION";
      }
    }
    // agent.last_action from the newest actionable feed item
    var feed = data.feed || [];
    if (data.agent && !data.agent.last_action) {
      for (var i = 0; i < feed.length; i++) {
        var k = (feed[i] && feed[i].kind) || "";
        var when = hhmm(feed[i].ts) ? " · " + hhmm(feed[i].ts) + " UTC" : "";
        if (k === "OPENED" || k === "CLOSED") {
          data.agent.last_action =
            k + (feed[i].symbol ? " " + feed[i].symbol : "") + when;
          break;
        }
        if (k === "CYCLE" || k === "SKIPPED" || k === "DAY_CLOSE") {
          data.agent.last_action = "STOOD DOWN" + when;
          break;
        }
      }
    }
    if (!data.fills) data.fills = { count: tb.fills !== undefined ? tb.fills : null };
    // chain verify runs at snapshot generation time; its recomputed chain
    // head doubles as the honest verification digest
    if (!data.verify) {
      var vts = data.meta ? Date.parse(data.meta.generated_at) : NaN;
      data.verify = {
        last_ts: isNaN(vts) ? null : fmtSiteTs(vts),
        result: tb.chain_integrity || null,
        digest: (data.journal && data.journal.head_hash_prefix)
          ? "0x" + data.journal.head_hash_prefix : null
      };
    }
    // live actor's badge (actors[0] = ACOS AGENT), display-ready:
    // CAPS status, site-format issue date, on-chain tx for the scan link
    if (!data.badge) {
      var actors = data.actors && data.actors.actors;
      var a0 = actors && actors[0];
      if (a0 && a0.badge) {
        var bts = Date.parse(a0.badge.issued_at);
        var bd = isNaN(bts) ? null : new Date(bts);
        data.badge = {
          status: String(a0.badge.status || "").toUpperCase(),
          response: a0.badge.response,
          issued_at: a0.badge.issued_at,
          issued: bd ? pad2(bd.getUTCDate()) + " " + MON[bd.getUTCMonth()] + " " + bd.getUTCFullYear() : null,
          tx: (a0.tx_refs && a0.tx_refs[0] && a0.tx_refs[0].tx) || null
        };
      } else {
        data.badge = null;
      }
    }
    // last_trade: canvas prints raw values - hand it display-ready strings
    // (site typography: "01 JUL, 02:00 UTC"; reasons in CAPS; no fake peak)
    var ltDisplay = null;
    if (data.last_trade) {
      ltDisplay = {};
      for (var lk in data.last_trade) {
        if (Object.prototype.hasOwnProperty.call(data.last_trade, lk)) ltDisplay[lk] = data.last_trade[lk];
      }
      var lts = Date.parse(ltDisplay.ts);
      if (!isNaN(lts)) ltDisplay.ts = fmtSiteTs(lts);
      if (ltDisplay.exit_reason) ltDisplay.exit_reason = String(ltDisplay.exit_reason).toUpperCase();
      if (ltDisplay.peak_pnl_usd === null || ltDisplay.peak_pnl_usd === undefined) ltDisplay.peak_pnl_usd = MISSING;
    }
    // canvas feed: objects with a preformatted .line, newest LAST
    var lines = [];
    for (var j = feed.length - 1; j >= 0; j--) {
      var it = feed[j] || {};
      lines.push({
        line: hhmm(it.ts) + " " + (it.kind || "") + " · " + (it.text || ""),
        ts: it.ts, kind: it.kind,
        arc_tx: it.refs && it.refs.arc_tx,
        arc_block: it.refs && it.refs.arc_block,
        btc_block: it.refs && it.refs.btc_block
      });
    }
    var out = {};
    for (var key in data) if (Object.prototype.hasOwnProperty.call(data, key)) out[key] = data[key];
    out.feed = lines;
    if (ltDisplay) out.last_trade = ltDisplay;
    return out;
  }

  function fetchSnapshot() {
    fetch(SNAPSHOT_URL, { cache: "no-store" })
      .then(function (resp) {
        if (!resp.ok) throw new Error("http " + resp.status);
        return resp.json();
      })
      .then(function (data) {
        snapshot = data;
        var gen = get(data, "meta.generated_at");
        var t = Date.parse(gen);
        generatedAtMs = isNaN(t) ? null : t;
        document.body.classList.remove("state-offline");
        applyBindings(false, false);
        renderFeed();
        updateStale();
        // WebGL bridge: expose + announce the fresh snapshot (kept on failure).
        // ACOS_DATA gets the canvas-adapted view (derived paths + line-feed).
        var forCanvas = enrichForCanvas(data);
        window.ACOS_DATA = forCanvas;
        document.dispatchEvent(new CustomEvent("acos:data", { detail: forCanvas }));
      })
      .catch(function () {
        // keep the last rendered values; just flag the page offline
        document.body.classList.add("state-offline");
      });
  }

  function start() {
    fetchSnapshot();
    setInterval(fetchSnapshot, REFRESH_MS);
    setInterval(function () { applyBindings(true, false); }, 60 * 1000);
    setInterval(function () {
      applyBindings(true, true);
      updateStale();
    }, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
