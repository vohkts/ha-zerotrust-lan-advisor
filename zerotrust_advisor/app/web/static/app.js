// Highlights the current page in the sidebar. Done in JS rather than
// passing an "active page" variable through every route/template: the last
// path segment (Ingress prefix and all) already tells us which page this
// is, matched against each nav link's own relative href. "settings" isn't
// its own nav link (Setup & Settings share one, at "setup") — a Settings
// save renders that same combined page directly at the /settings URL, so
// it needs to map onto the same link rather than match nothing.
const currentSegment = window.location.pathname.split("/").filter(Boolean).pop();
const navSegment = currentSegment === "settings" ? "setup" : currentSegment;
for (const link of document.querySelectorAll("nav [data-nav]")) {
  if (link.getAttribute("href") === navSegment) link.classList.add("active");
}

// Buttons with data-action post to that relative URL and reload on success.
// Using fetch() rather than a normal form submit keeps the browser's
// address bar on the current page — which matters under Ingress, where
// every link in this app is relative to whatever page is currently shown.
// "Run analysis now" is deliberately not one of these — see its own
// handler below, which needs to poll for progress instead of just
// reloading once a single request resolves.
document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;

  button.disabled = true;
  // Buttons with data-form-body="closest" (e.g. the network rename form)
  // send their enclosing form's fields as the POST body; everything else
  // posts with no body, same as before.
  const options = { method: "POST" };
  if (button.dataset.formBody === "closest") {
    options.body = new FormData(button.closest("form"));
  }
  try {
    const response = await fetch(button.dataset.action, options);
    if (!response.ok && response.status !== 409) {
      throw new Error(`request failed: ${response.status}`);
    }
    window.location.reload();
  } catch (err) {
    button.disabled = false;
  }
});

// "Run analysis now" — this can genuinely take anywhere from a few
// seconds (nothing new) to several minutes (each new pattern needs its
// own LLM call, roughly a minute on typical hardware), and a plain
// disabled button with no feedback for that long reads as frozen, not
// busy. Every recommendation commits to the database the instant it's
// found (see engine.py), so polling the live count while this runs is
// real progress, not a fake spinner.
const runNowBtn = document.getElementById("run-now");
if (runNowBtn) {
  runNowBtn.addEventListener("click", async () => {
    const statusEl = document.getElementById("run-now-status");
    runNowBtn.disabled = true;

    let baseline = { zero_trust_count: 0, setup_count: 0 };
    try {
      baseline = await (await fetch("recommendations/progress")).json();
    } catch {
      // Fine to proceed without a baseline — progress text just won't
      // have a "new since you clicked" count to show.
    }

    statusEl.textContent =
      "Running… this can take from a few seconds to several minutes, roughly a minute per new pattern found.";

    const pollTimer = setInterval(async () => {
      try {
        const body = await (await fetch("recommendations/progress")).json();
        const newZt = body.zero_trust_count - baseline.zero_trust_count;
        const newSetup = body.setup_count - baseline.setup_count;
        if (newZt > 0 || newSetup > 0) {
          statusEl.textContent = `Running… ${newZt} new recommendation(s), ${newSetup} new setup finding(s) so far.`;
        }
      } catch {
        // A missed poll just means one stale status update — the next
        // tick (or the final response below) will catch up.
      }
    }, 4000);

    try {
      const response = await fetch("recommendations/run-now", { method: "POST" });
      if (!response.ok && response.status !== 409) {
        throw new Error(`request failed: ${response.status}`);
      }
      const body = await response.json();
      statusEl.textContent =
        body.status === "already_running"
          ? "An analysis pass is already running."
          : `Done — ${body.new_recommendations} new recommendation(s), ${body.new_setup_findings} new setup finding(s).`;
      window.location.reload();
    } catch (err) {
      runNowBtn.disabled = false;
      statusEl.textContent = `Something went wrong: ${err.message}`;
    } finally {
      clearInterval(pollTimer);
    }
  });
}

// UniFi "Test connection" — posts the fieldset's current values (not
// necessarily saved yet) and renders per-capability results inline.
// Deliberately its own handler, not a data-action button: those reload the
// page on success, which would wipe out an API key the user just typed but
// hasn't saved yet.
const unifiTestBtn = document.getElementById("unifi-test-btn");
if (unifiTestBtn) {
  unifiTestBtn.addEventListener("click", async () => {
    const resultEl = document.getElementById("unifi-test-result");
    // FormData only accepts an actual <form>, not the <fieldset> around
    // these inputs — this used to pass the fieldset directly, which throws
    // a TypeError before the request is even sent. Every other field in
    // the enclosing settings form rides along harmlessly; the server route
    // only reads the three unifi_* fields it cares about.
    const form = unifiTestBtn.closest("form");
    unifiTestBtn.disabled = true;
    resultEl.textContent = "Testing…";
    resultEl.className = "unifi-test-result";

    try {
      const response = await fetch("settings/unifi/test", { method: "POST", body: new FormData(form) });
      const rawText = await response.text();
      let body;
      try {
        body = JSON.parse(rawText);
      } catch {
        // Something between the browser and this add-on (Ingress, a proxy
        // timeout) answered with a non-JSON page instead of our route ever
        // running — show what actually came back rather than a fixed
        // string that hides it.
        resultEl.textContent = `Unexpected response (HTTP ${response.status}): ${rawText.slice(0, 200) || "(empty body)"}`;
        resultEl.classList.add("unifi-test-fail");
        return;
      }
      if (!response.ok) {
        const messages = { missing_host: "Enter a console IP or hostname first.", missing_api_key: "Enter an API key first." };
        resultEl.textContent = messages[body.error] || body.detail || `Connection test failed (${body.error || response.status}).`;
        resultEl.classList.add("unifi-test-fail");
      } else {
        const lines = body.capabilities.map((c) => `${c.ok ? "✓" : "✗"} ${c.label} — ${c.detail}`);
        resultEl.textContent = lines.join("\n");
        resultEl.classList.add(body.any_capability_ok ? "unifi-test-ok" : "unifi-test-fail");
      }
    } catch (err) {
      resultEl.textContent = `Request failed: ${err.message}`;
      resultEl.classList.add("unifi-test-fail");
    } finally {
      unifiTestBtn.disabled = false;
    }
  });
}

// Client-side tab toggle (Zero-Trust Rules / Setup & Tuning) — no
// navigation, so it can't run into the relative-URL depth issue a second
// route at /recommendations/setup would (see routes_recommendations.py).
document.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-tab]");
  if (!toggle) return;

  for (const el of document.querySelectorAll("[data-tab].tab-toggle")) {
    el.classList.toggle("active", el === toggle);
  }
  for (const panel of document.querySelectorAll("[data-tab-panel]")) {
    panel.hidden = panel.dataset.tabPanel !== toggle.dataset.tab;
  }
});

// Client-side pagination (UniFi's policies list alone can run into the
// hundreds) plus optional live text filtering, for any data table.
// Everything is already rendered server-side in one page load — no new
// route, no re-fetch — this just hides rows and adds Previous/Next
// controls after the table. Pagination applies automatically to every
// table over PAGE_SIZE rows; a short table is left alone unless it also
// has a filter input. Filtering only runs where a page explicitly adds
// <input data-filter-for="table-id"> above a table (see network.html) —
// matches against the row's full text, case-insensitive, so one box
// covers name/IP/MAC/vendor/zone/etc. without a filter per column.
const TABLE_PAGE_SIZE = 25;

function setupTable(table) {
  const tbody = table.querySelector("tbody");
  if (!tbody) return;
  const allRows = Array.from(tbody.querySelectorAll("tr"));
  if (allRows.length === 0) return;

  const controls = document.createElement("div");
  controls.className = "table-pagination";
  table.insertAdjacentElement("afterend", controls);

  let query = "";
  let page = 0;

  function render() {
    const matching = query ? allRows.filter((row) => row.textContent.toLowerCase().includes(query)) : allRows;
    const totalPages = Math.max(1, Math.ceil(matching.length / TABLE_PAGE_SIZE));
    if (page >= totalPages) page = 0;
    const start = page * TABLE_PAGE_SIZE;
    const visible = new Set(matching.slice(start, start + TABLE_PAGE_SIZE));
    for (const row of allRows) row.hidden = !visible.has(row);

    const needsControls = matching.length > TABLE_PAGE_SIZE || (query && matching.length !== allRows.length);
    if (!needsControls) {
      controls.replaceChildren();
      return;
    }

    const prev = document.createElement("button");
    prev.type = "button";
    prev.textContent = "Previous";
    prev.disabled = page === 0;
    prev.addEventListener("click", () => {
      page -= 1;
      render();
    });

    const status = document.createElement("span");
    status.className = "hint";
    status.textContent = query
      ? `Page ${page + 1} of ${totalPages} (${matching.length} of ${allRows.length} match)`
      : `Page ${page + 1} of ${totalPages} (${allRows.length} total)`;

    const next = document.createElement("button");
    next.type = "button";
    next.textContent = "Next";
    next.disabled = page === totalPages - 1;
    next.addEventListener("click", () => {
      page += 1;
      render();
    });

    controls.replaceChildren(prev, status, next);
  }

  table._ztaSetFilter = (q) => {
    query = q.trim().toLowerCase();
    page = 0;
    render();
  };

  render();
}

document.querySelectorAll("table.status-table").forEach(setupTable);

document.querySelectorAll("[data-filter-for]").forEach((input) => {
  const table = document.getElementById(input.dataset.filterFor);
  if (!table || !table._ztaSetFilter) return;
  input.addEventListener("input", () => table._ztaSetFilter(input.value));
});
