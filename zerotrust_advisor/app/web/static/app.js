// Buttons with data-action post to that relative URL and reload on success.
// Using fetch() rather than a normal form submit keeps the browser's
// address bar on the current page — which matters under Ingress, where
// every link in this app is relative to whatever page is currently shown.
document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;

  button.disabled = true;
  const statusEl = document.getElementById("run-now-status");
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
    if (button.id === "run-now" && statusEl) {
      const body = await response.json();
      statusEl.textContent =
        body.status === "already_running"
          ? "An analysis pass is already running."
          : `Done — ${body.new_recommendations} new recommendation(s), ${body.new_setup_findings} new setup finding(s).`;
    }
    window.location.reload();
  } catch (err) {
    button.disabled = false;
    if (statusEl) statusEl.textContent = "Something went wrong — check the add-on logs.";
  }
});

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
