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
// own LLM call, roughly a minute on typical hardware). The POST below
// only *starts* the pass in a background thread and returns right away
// (see routes_recommendations.py) — waiting on the full pass here used to
// get the request killed with a 504 by the proxy chain in front of this
// add-on, reported live. Completion is detected the same way progress
// is: polling, watching `running` flip back to False, not by waiting on
// this fetch to resolve.
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

    try {
      const response = await fetch("recommendations/run-now", { method: "POST" });
      if (!response.ok && response.status !== 409) {
        throw new Error(`request failed: ${response.status}`);
      }
      const body = await response.json();
      if (body.status === "already_running") {
        statusEl.textContent = "An analysis pass is already running.";
        runNowBtn.disabled = false;
        return;
      }
    } catch (err) {
      runNowBtn.disabled = false;
      statusEl.textContent = `Something went wrong: ${err.message}`;
      return;
    }

    statusEl.textContent =
      "Running… this can take from a few seconds to several minutes, roughly a minute per new pattern found.";

    const pollTimer = setInterval(async () => {
      let body;
      try {
        body = await (await fetch("recommendations/progress")).json();
      } catch {
        return; // a missed poll just means one stale status update; the next tick catches up
      }
      const newZt = body.zero_trust_count - baseline.zero_trust_count;
      const newSetup = body.setup_count - baseline.setup_count;
      if (body.running) {
        statusEl.textContent = `Running… ${newZt} new recommendation(s), ${newSetup} new setup finding(s) so far.`;
        return;
      }
      clearInterval(pollTimer);
      statusEl.textContent = `Done — ${newZt} new recommendation(s), ${newSetup} new setup finding(s).`;
      window.location.reload();
    }, 4000);
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
    // Any expand-on-click detail row (see the Hosts table) is inserted
    // into the DOM after this table's row snapshot was taken, so it isn't
    // one of allRows and paging away from it would leave it orphaned and
    // visible under whatever page happens to be showing next — simplest
    // fix is to always collapse it on any page change.
    for (const row of tbody.querySelectorAll(".host-detail-row")) row.remove();

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

// [data-no-paginate] opts a table out entirely — the Live View table
// manages its own rows via a continuous poll (see live.html); paginating
// it against a snapshot of rows taken at page-load time would silently
// stop reflecting anything appended after that snapshot.
document.querySelectorAll("table.status-table:not([data-no-paginate])").forEach(setupTable);

document.querySelectorAll("[data-filter-for]").forEach((input) => {
  const table = document.getElementById(input.dataset.filterFor);
  if (!table || !table._ztaSetFilter) return;
  input.addEventListener("input", () => table._ztaSetFilter(input.value));
});

// Live View — polls for new firewall events and appends them to a
// continuously-growing table (capped at MAX_ROWS, trimming the oldest).
// Off by default: nothing is fetched until Start is clicked. Stop halts
// polling but leaves the table exactly as it was; Clear only empties the
// table, independent of whether polling is currently active.
const liveToggleBtn = document.getElementById("live-toggle");
if (liveToggleBtn) {
  const tbody = document.getElementById("live-table-body");
  const statusDot = document.getElementById("live-status-dot");
  const statusText = document.getElementById("live-status-text");
  const emptyHint = document.getElementById("live-empty-hint");
  const clearBtn = document.getElementById("live-clear");
  const MAX_ROWS = 300;
  const POLL_MS = 1500;

  let cursor = 0;
  let pollTimer = null;
  let active = false;

  function cell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
  }

  function addRow(ev) {
    const tr = document.createElement("tr");
    tr.className = "live-row-new";

    const port = ev.dst_port != null ? ev.dst_port : "any";
    const portCell = `${ev.proto}/${port}` + (ev.port_hint ? ` — ${ev.port_hint}` : "");
    const srcCell = ev.src_ip + (ev.src_port ? `:${ev.src_port}` : "");

    const statusTd = document.createElement("td");
    const chip = document.createElement("span");
    chip.className = `chip ${ev.blocked ? "chip-danger" : "chip-ok"}`;
    chip.textContent = ev.action || (ev.blocked ? "blocked" : "allowed");
    statusTd.appendChild(chip);

    tr.append(
      cell(new Date(ev.ts * 1000).toLocaleTimeString()),
      cell(srcCell),
      cell(ev.dst_ip),
      cell(portCell),
      statusTd,
    );
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.lastChild);
    emptyHint.hidden = true;
  }

  async function poll() {
    try {
      const body = await (await fetch(`live/events?since_id=${cursor}`)).json();
      cursor = body.max_id;
      for (const ev of body.events) addRow(ev);
    } catch {
      // A missed poll just means one gap in an otherwise live feed — the next tick retries.
    }
  }

  async function start() {
    try {
      cursor = (await (await fetch("live/events")).json()).max_id;
    } catch {
      cursor = 0;
    }
    active = true;
    liveToggleBtn.textContent = "Stop";
    statusDot.classList.add("live-active");
    statusText.textContent = "Live — watching for new events…";
    pollTimer = setInterval(poll, POLL_MS);
  }

  function stop() {
    active = false;
    clearInterval(pollTimer);
    liveToggleBtn.textContent = "Start";
    statusDot.classList.remove("live-active");
    statusText.textContent = "Stopped";
  }

  liveToggleBtn.addEventListener("click", () => (active ? stop() : start()));
  clearBtn.addEventListener("click", () => {
    tbody.replaceChildren();
    emptyHint.hidden = false;
  });
}

// Hosts table: click a row to expand an inline panel with its behavior
// detail (see routes_traffic.py's /traffic/host-detail). Built with plain
// DOM calls throughout, never innerHTML with fetched text — a device's
// hostname (mDNS/UniFi-sourced) or an LLM's own guess text both come from
// outside this app's control, however unlikely either is to be hostile.
document.addEventListener("click", async (event) => {
  const row = event.target.closest("tr[data-host-ip]");
  if (!row) return;

  const existing = row.nextElementSibling;
  if (existing && existing.classList.contains("host-detail-row")) {
    existing.remove();
    return;
  }
  // Collapse any other open panel in this table — one at a time keeps it simple.
  for (const open of row.closest("tbody").querySelectorAll(".host-detail-row")) open.remove();

  const ip = row.dataset.hostIp;
  const colCount = row.children.length;
  const detailRow = document.createElement("tr");
  detailRow.className = "host-detail-row";
  const detailCell = document.createElement("td");
  detailCell.colSpan = colCount;
  detailCell.textContent = "Loading…";
  detailRow.appendChild(detailCell);
  row.after(detailRow);

  await loadAndRenderHostDetail(ip, detailCell);
});

function labeledList(title, items, formatItem) {
  const wrap = document.createElement("div");
  wrap.className = "host-detail-block";
  const h = document.createElement("h4");
  h.textContent = title;
  wrap.appendChild(h);
  if (items.length === 0) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "None observed.";
    wrap.appendChild(p);
    return wrap;
  }
  const ul = document.createElement("ul");
  ul.className = "host-detail-list";
  for (const item of items) {
    const li = document.createElement("li");
    formatItem(li, item);
    ul.appendChild(li);
  }
  wrap.appendChild(ul);
  return wrap;
}

async function loadAndRenderHostDetail(ip, container) {
  let data;
  try {
    data = await (await fetch(`traffic/host-detail?ip=${encodeURIComponent(ip)}`)).json();
  } catch (err) {
    container.textContent = `Failed to load: ${err.message}`;
    return;
  }

  container.replaceChildren();
  const root = document.createElement("div");
  root.className = "host-detail";

  const summary = document.createElement("p");
  summary.className = "hint";
  summary.textContent =
    `${data.event_count} event(s) in the last ${data.window_days} days` +
    (data.first_seen ? ` — first seen ${new Date(data.first_seen * 1000).toLocaleString()}` : "");
  root.appendChild(summary);

  root.appendChild(
    labeledList("Most common ports", data.top_ports, (li, p) => {
      const port = p.port != null ? p.port : "any";
      li.textContent = `${p.proto}/${port}${p.port_hint ? " — " + p.port_hint : ""} — ${p.count} time(s)`;
    })
  );

  root.appendChild(
    labeledList("Talks to most often", data.top_partners, (li, partner) => {
      const label = partner.name || partner.device_class || partner.ip;
      li.textContent = `${label} (${partner.network}) — ${partner.count} time(s)`;
    })
  );

  root.appendChild(
    labeledList("Recent distinct flows", data.recent_flows, (li, f) => {
      const port = f.port != null ? f.port : "any";
      li.textContent =
        `${f.src} (${f.src_network}) → ${f.dst} (${f.dst_network}) — ${f.proto}/${port}` +
        `${f.port_hint ? " — " + f.port_hint : ""} — ${f.count}x`;
    })
  );

  if (data.device_class === "Unclassified device") {
    const guessBlock = document.createElement("div");
    guessBlock.className = "host-detail-block";
    const h = document.createElement("h4");
    h.textContent = "What might this be?";
    guessBlock.appendChild(h);

    if (data.llm_guess) {
      const p = document.createElement("p");
      p.textContent = data.llm_guess;
      guessBlock.appendChild(p);
    } else if (data.guess_in_progress) {
      const p = document.createElement("p");
      p.className = "hint";
      p.textContent = "Generating a guess (can take up to a minute)…";
      guessBlock.appendChild(p);
      pollForGuess(ip, guessBlock, p);
    } else {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = "Guess with AI";
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        const p = document.createElement("p");
        p.className = "hint";
        p.textContent = "Generating a guess (can take up to a minute)…";
        guessBlock.replaceChildren(h, p);
        try {
          await fetch(`traffic/host-detail/guess?ip=${encodeURIComponent(ip)}`, { method: "POST" });
        } catch {
          // Fall through to polling regardless — it'll just find no guess yet.
        }
        pollForGuess(ip, guessBlock, p);
      });
      guessBlock.appendChild(btn);
    }
    root.appendChild(guessBlock);
  }

  container.appendChild(root);
}

function pollForGuess(ip, guessBlock, statusEl) {
  const timer = setInterval(async () => {
    let data;
    try {
      data = await (await fetch(`traffic/host-detail?ip=${encodeURIComponent(ip)}`)).json();
    } catch {
      return;
    }
    if (data.llm_guess) {
      clearInterval(timer);
      const p = document.createElement("p");
      p.textContent = data.llm_guess;
      statusEl.replaceWith(p);
    } else if (!data.guess_in_progress) {
      clearInterval(timer);
      statusEl.textContent = "Something went wrong generating a guess — check the add-on logs.";
    }
  }, 4000);
}
