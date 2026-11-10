// Common UI utilities.

// Translation: t("Texto en español {n}", {n: 3}). window.I18N only has data when the language is English.
function t(text, vars) {
  let s = (window.I18N || {})[text] ?? text;
  for (const [k, v] of Object.entries(vars || {})) s = s.split(`{${k}}`).join(v);
  return s;
}

async function api(url, body) {
  const r = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("session expired"); }
  return r.json();
}

// Quick text filter for tables: <input data-filter="#tabla">
document.querySelectorAll("input[data-filter]").forEach((inp) => {
  const table = document.querySelector(inp.dataset.filter);
  inp.addEventListener("input", () => {
    const q = inp.value.toLowerCase();
    table.querySelectorAll("tbody tr").forEach((tr) => {
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
    });
  });
});

// Sort tables by clicking the header (th.sortable)
document.querySelectorAll("th.sortable").forEach((th) => {
  th.addEventListener("click", () => {
    const table = th.closest("table");
    const idx = [...th.parentNode.children].indexOf(th);
    const asc = th.dataset.dir !== "asc";
    th.parentNode.querySelectorAll("th[data-dir]").forEach((o) => { delete o.dataset.dir; });  // only one active arrow
    th.dataset.dir = asc ? "asc" : "desc";
    const rows = [...table.tBodies[0].rows];
    const val = (r) => r.cells[idx].dataset.sort ?? r.cells[idx].textContent.trim();
    rows.sort((a, b) => {
      const x = val(a), y = val(b);
      const nx = parseFloat(x), ny = parseFloat(y);
      const c = !isNaN(nx) && !isNaN(ny) ? nx - ny : x.localeCompare(y, "es", { numeric: true });
      return asc ? c : -c;
    });
    rows.forEach((r) => table.tBodies[0].appendChild(r));
    if (table.repage) table.repage();   // paginated tables go back to page 1 with the new order
  });
});

// Paginated tables: <table class="paged" data-page-size="8"> followed by <div class="pager">
// Rows with data-out="1" are filtered out (table.repage() recomputes the pages after filtering).
document.querySelectorAll("table.paged").forEach((table) => {
  const size = parseInt(table.dataset.pageSize || "10", 10);
  const pager = table.nextElementSibling;
  if (!pager || !pager.classList.contains("pager")) return;
  (table.repage = () => {
    const all = [...table.tBodies[0].rows];
    const rows = all.filter((r) => r.dataset.out !== "1");
    all.forEach((r) => { if (r.dataset.out === "1") r.hidden = true; });
    const pages = Math.ceil(rows.length / size);
    const show = (page) => {
      rows.forEach((r, i) => { r.hidden = Math.floor(i / size) !== page; });
      pager.querySelectorAll("button").forEach((b, i) => b.classList.toggle("on", i === page));
    };
    pager.innerHTML = pages > 1 ? Array.from({ length: pages }, (_, i) => `<button type="button">${i + 1}</button>`).join("") : "";
    pager.querySelectorAll("button").forEach((b, i) => { b.onclick = () => show(i); });
    show(0);
  })();
});

// "Select all" checkboxes
document.querySelectorAll("input[data-check-all]").forEach((all) => {
  all.addEventListener("change", () => {
    document.querySelectorAll(all.dataset.checkAll).forEach((c) => {
      if (c.closest("tr, label")?.style.display !== "none") c.checked = all.checked;
    });
    document.dispatchEvent(new Event("selection-changed"));
  });
});

// Tabs: <div class="tabs"><a data-tab="x">...</a></div> + <div class="tab" id="tab-x">
document.querySelectorAll(".tabs a[data-tab]").forEach((a) => {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    document.querySelectorAll(".tabs a").forEach((x) => x.classList.toggle("active", x === a));
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + a.dataset.tab));
    history.replaceState(null, "", "#" + a.dataset.tab);
  });
});
if (location.hash) document.querySelector(`.tabs a[data-tab="${location.hash.slice(1)}"]`)?.click();

// Multi-select dropdowns (_multi.html): summary, search and closing on outside click
function multiValues(name) {
  return [...document.querySelectorAll(`details.multi[data-multi="${name}"] input[type=checkbox]:checked`)].map((c) => c.value);
}
// Programmatically checks the values of a multi-select dropdown (e.g. when opening the chart editor)
function setMulti(name, values) {
  const d = document.querySelector(`details.multi[data-multi="${name}"]`);
  if (!d) return;
  const chosen = new Set((values || []).map(String));
  d.querySelectorAll("input[type=checkbox]").forEach((c) => { c.checked = chosen.has(c.value); });
  d.update();
}
// Visible text of the chosen values (to describe filters)
function multiLabels(name, values) {
  return (values || []).map((v) =>
    t(document.querySelector(`details.multi[data-multi="${name}"] input[value="${CSS.escape(String(v))}"]`)?.dataset.label || v));
}
document.querySelectorAll("details.multi").forEach((d) => {
  const summary = d.querySelector("summary");
  const update = d.update = () => {
    const labels = [...d.querySelectorAll("input[type=checkbox]:checked")].map((c) => t(c.dataset.label));
    summary.textContent = !labels.length ? t(d.dataset.all) : labels.length <= 2 ? labels.join(", ")
      : t("{n} selected", { n: labels.length });
    d.dispatchEvent(new Event("multi-change", { bubbles: true }));
  };
  d.addEventListener("change", (e) => { if (e.target.type === "checkbox") update(); });
  const search = d.querySelector(".multi-search");
  if (search) search.addEventListener("input", () => {
    const q = search.value.toLowerCase();
    d.querySelectorAll("label").forEach((l) => { l.style.display = l.textContent.toLowerCase().includes(q) ? "" : "none"; });
  });
});
document.addEventListener("click", (e) => {
  document.querySelectorAll("details.multi[open]").forEach((d) => { if (!d.contains(e.target)) d.open = false; });
});

// Dropdowns with "+ Create new…": show a text field when that option is chosen
document.querySelectorAll("select[data-creatable]").forEach((sel) => {
  const input = sel.parentElement.querySelector(`input[name="${sel.name}_new"]`);
  const sync = () => {
    input.hidden = sel.value !== "__new__";
    input.required = !input.hidden;
    if (!input.hidden) input.focus();
  };
  sel.addEventListener("change", sync);
});

// Confirmation on dangerous forms: <form data-confirm="¿Seguro?">
document.querySelectorAll("form[data-confirm]").forEach((f) => {
  f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
});
// ...or on a specific button: <button data-confirm="¿Seguro?">
document.querySelectorAll("button[data-confirm]").forEach((b) => {
  b.addEventListener("click", (e) => { if (!confirm(b.dataset.confirm)) e.preventDefault(); });
});

// Asks the user for credentials that are not saved. Returns {username, password, ...} or null.
function askAuth(missing) {
  const dlg = document.getElementById("auth-dlg"), form = document.getElementById("auth-form");
  const needUser = missing.some((m) => m.missing === "user");
  document.getElementById("auth-intro").textContent = t("These {n} server(s) have no saved user or password:", { n: missing.length });
  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
  const shown = missing.slice(0, 15).map((m) => `<li>${esc(m.name)} <span class="muted">${esc(m.host)}</span></li>`);
  if (missing.length > 15) shown.push(`<li class="muted">${t("and {n} more", { n: missing.length - 15 })}</li>`);
  document.getElementById("auth-list").innerHTML = shown.join("");
  document.getElementById("auth-user-box").hidden = !needUser;
  form.elements.username.required = needUser;
  form.reset();
  dlg.showModal();
  const skipBtn = document.getElementById("auth-skip"), cancelBtn = document.getElementById("auth-cancel");
  return new Promise((resolve) => {
    const done = (value) => { form.onsubmit = skipBtn.onclick = cancelBtn.onclick = null; dlg.close(); resolve(value); };
    form.onsubmit = (e) => {
      e.preventDefault();
      done({ username: form.elements.username.value.trim(), password: form.elements.password.value,
             sudo_password: form.elements.sudo_password.value, remember: form.elements.remember.checked });
    };
    skipBtn.onclick = () => done("skip");
    cancelBtn.onclick = () => done(null);
  });
}

// POST that, if the server replies that credentials are missing, asks for them (or skips those VMs) and retries.
// Also handles the safe-mode warning.
async function apiWithAuth(url, body) {
  let r = await api(url, body);
  if (r.stepup) {
    if (!(await askStepup("remote execution"))) return null;
    r = await api(url, body);
  }
  if (r.danger) {
    // Safe mode: CONFIRM must be typed (danger.js)
    if (!(await askDangerConfirm(r.danger, body.command || ""))) return null;
    body = { ...body, confirm_danger: CONFIRM_WORD };
    r = await api(url, body);
  }
  if (r.need_auth) {
    const auth = await askAuth(r.need_auth);
    if (!auth) return null;
    const extra = auth === "skip" ? { exclude: r.need_auth.map((m) => m.id) } : { auth };
    r = await api(url, { ...body, ...extra });
  }
  if (r.error) { alert(t(r.error)); return null; }
  return r;
}

// Scans: starts them and monitors until they finish, then reloads.
async function startScan(payload) {
  const r = await apiWithAuth("/api/scan", payload);
  if (!r) return;
  if (!r.started) { alert(t("No servers to scan (do they have a credential assigned?) or they are already being scanned.")); return; }
  watchScans();
}

let scanWatcher = null;
function watchScans() {
  if (scanWatcher) return;
  const box = document.getElementById("scan-status");
  scanWatcher = setInterval(async () => {
    const r = await api("/api/scan/status");
    const ids = Object.keys(r.running);
    document.querySelectorAll("[data-scan-vm]").forEach((el) => {
      const st = r.running[el.dataset.scanVm];
      if (st) el.innerHTML = `<span class="spin"></span> ${st === "queued" ? t("queued") : t("scanning")}`;
    });
    if (box) box.innerHTML = ids.length ? `<span class="spin"></span> ${t("Scanning {n} server(s)...", { n: ids.length })}` : "";
    if (!ids.length) { clearInterval(scanWatcher); scanWatcher = null; location.reload(); }
  }, 2000);
}

function selectedIds(selector) {
  return [...document.querySelectorAll(selector)].filter((c) => c.checked).map((c) => parseInt(c.value));
}

// Step-up verification: asks for the master password (valid for 5 minutes)
function askMasterPassword() {
  const dlg = document.getElementById("stepup-dlg"), form = document.getElementById("stepup-form");
  form.reset();
  dlg.showModal();
  return new Promise((resolve) => {
    const done = (v) => { form.onsubmit = null; document.getElementById("stepup-cancel").onclick = null; dlg.close(); resolve(v); };
    form.onsubmit = (e) => { e.preventDefault(); done(form.elements.password.value); };
    document.getElementById("stepup-cancel").onclick = () => done(null);
  });
}

async function askStepup(what) {
  const pw = await askMasterPassword();
  if (!pw) return false;
  const r = await api("/api/stepup", { password: pw, what });
  if (!r.ok) { alert(t(r.error || "Wrong master password")); return false; }
  return true;
}

// Show a saved password (asks for the master password and is logged in the audit log)
async function reveal(id, btn) {
  if (!confirm(t("The password will be shown on screen and this will be recorded in the audit log. Continue?"))) return;
  let r = await api(`/api/credentials/${id}/reveal`, {});
  if (r.stepup) {
    if (!(await askStepup("show password"))) return;
    r = await api(`/api/credentials/${id}/reveal`, {});
  }
  const out = btn.nextElementSibling;
  out.textContent = r.password + (r.sudo_password ? `  (sudo: ${r.sudo_password})` : "");
  out.hidden = false;
  setTimeout(() => { out.textContent = ""; out.hidden = true; }, 20000);
}

// Activity bar: scans, remote runs and open terminals (polled every 3 s).
const activityBox = document.getElementById("activity");
async function refreshActivity() {
  if (!activityBox || document.hidden) return;
  let a;
  try { a = await api("/api/activity"); } catch { return; }
  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
  const items = [];
  if (a.scans.length) {
    const running = a.scans.filter((s) => s.state === "running"), queued = a.scans.length - running.length;
    const names = running.slice(0, 3).map((s) => esc(s.name)).join(", ") + (running.length > 3 ? "…" : "");
    items.push(`<a class="act" href="/vms"><span class="spin"></span> ${t("Scanning {n} server(s)", { n: a.scans.length })}` +
      `${queued ? ` · ${t("{n} queued", { n: queued })}` : ""}${names ? ` <span class="muted">(${names})</span>` : ""}</a>`);
  }
  for (const j of a.jobs) {
    items.push(`<a class="act" href="/jobs/${j.id}"><span class="spin"></span> ${t("Run #{n}", { n: j.id })}: ` +
      `<code>${esc(j.command.length > 40 ? j.command.slice(0, 40) + "…" : j.command)}</code> · ${j.done}/${j.target_count}</a>`);
  }
  for (const s of a.terminals) {
    items.push(`<span class="act">&gt;_ ${t("Terminal")}: <b>${esc(s.vm_name)}</b>${s.become ? " (sudo su - " + esc(s.become) + ")" : ""} ` +
      `<span class="muted">${t("since {h}", { h: s.since.slice(11, 16) })}</span></span>`);
  }
  activityBox.innerHTML = items.length ? `<span class="act-title">${t("In progress")}:</span> ` + items.join("") : "";
  activityBox.hidden = !items.length;
}
if (activityBox) { refreshActivity(); setInterval(refreshActivity, 3000); }

// If scans are in progress on load, watch them.
if (document.getElementById("scan-status")) {
  api("/api/scan/status").then((r) => { if (Object.keys(r.running).length) watchScans(); });
}
