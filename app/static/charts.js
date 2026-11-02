// Gráficos personalizables del Panel (Chart.js). Se recargan cuando cambia el inventario.

const container = document.getElementById("charts");
const editor = document.getElementById("editor");
const css = getComputedStyle(container);
const tok = (n) => css.getPropertyValue(n).trim();
const SERIES = [1, 2, 3, 4, 5, 6, 7].map((i) => tok(`--series-${i}`));
const OTHER = tok("--series-other");
const SURFACE = getComputedStyle(document.querySelector(".card, .kpi, main")).backgroundColor;
const TEXT = getComputedStyle(document.body).color;
const MUTED = tok("--axis");
const GRID = tok("--grid");
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const isOther = (l) => l.startsWith("Otros") || l.startsWith("(");

Chart.defaults.color = MUTED;
Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

let version = null;
let charts = [];
const instances = [];

// El color sigue a la categoría, no a su posición: se recuerda qué color tuvo cada etiqueta.
function colorsFor(chartId, labels) {
  let memo = {};
  try { memo = JSON.parse(localStorage.getItem("chart-colors-" + chartId) || "{}"); } catch { /* sin almacenamiento */ }
  const used = new Set();
  const out = labels.map((l) => {
    if (isOther(l)) return OTHER;
    const slot = memo[l];
    if (slot !== undefined && !used.has(slot)) { used.add(slot); return slot; }
    return null;
  });
  labels.forEach((l, i) => {
    if (out[i] !== null) return;
    const free = SERIES.findIndex((_, s) => !used.has(s));
    const slot = free === -1 ? 0 : free;
    used.add(slot);
    memo[l] = slot;
    out[i] = slot;
  });
  try { localStorage.setItem("chart-colors-" + chartId, JSON.stringify(memo)); } catch { /* sin almacenamiento */ }
  return out.map((c) => (typeof c === "number" ? SERIES[c] : c));
}

function describeFilters(c) {
  const f = c.filters || {}, parts = [];
  const list = (key) => { const v = f[key]; return !v ? [] : Array.isArray(v) ? v : [v]; };  // gráficos antiguos: un valor
  const names = (key) => multiLabels("f_" + key, list(key)).join(", ");
  if (list("client").length) parts.push(t("cliente {c}", { c: names("client") }));
  if (list("environment").length) parts.push(t("entorno {e}", { e: names("environment") }));
  if (list("tag").length) parts.push(t("etiqueta {t}", { t: names("tag") }));
  if (list("os_family").length) parts.push(names("os_family"));
  if (list("os_name").length) parts.push(names("os_name"));
  return parts.length ? t("Solo {f}", { f: parts.join(" · ") }) : "";
}

function render() {
  instances.splice(0).forEach((i) => i.destroy());
  if (!charts.length) {
    container.innerHTML = `<div class="card muted">${t("No hay gráficos. Pulsa")} <b>${t("+ Nuevo gráfico")}</b>.</div>`;
    return;
  }
  container.innerHTML = charts.map((c, idx) => {
    const n = c.data.labels.length;
    const h = c.kind === "bar" ? Math.max(120, n * 28 + 30) : 240;
    const sub = [describeFilters(c), c.dimension === "package_version" ? t("Paquete: {p}", { p: c.package }) : ""].filter(Boolean).join(" · ");
    return `<div class="chart-card">
      <div class="ch-head"><h2>${esc(c.title)}</h2>
        <span class="muted small">${t("{n} VMs", { n: c.data.total })}</span>
        <button title="${t("Mover a la izquierda")}" onclick="moveChart(${c.id},-1)" ${idx === 0 ? "disabled" : ""}>←</button>
        <button title="${t("Mover a la derecha")}" onclick="moveChart(${c.id},1)" ${idx === charts.length - 1 ? "disabled" : ""}>→</button>
        <button title="${t("Editar")}" onclick="openEditor(${c.id})">${t("Editar")}</button>
        <button title="${t("Eliminar")}" onclick="deleteChart(${c.id})">${t("Eliminar")}</button></div>
      ${sub ? `<div class="ch-sub">${esc(sub)}</div>` : ""}
      ${n ? `<div class="chart-box" style="height:${h}px"><canvas id="cv-${c.id}" role="img" aria-label="${esc(c.title)}"></canvas></div>
             ${c.kind !== "bar" ? `<ul class="chart-legend" id="lg-${c.id}"></ul>` : ""}`
          : `<p class="muted small">${t("Sin datos con estos filtros.")}</p>`}
    </div>`;
  }).join("");
  charts.forEach((c) => c.data.labels.length && draw(c));
}

function draw(c) {
  const { labels, values, links } = c.data;
  const total = values.reduce((a, b) => a + b, 0);
  const pct = (v) => (total ? Math.round((v / total) * 100) : 0);
  const go = (i) => { if (links[i]) location.href = links[i]; };
  const tooltip = {
    backgroundColor: "rgba(20,22,28,.95)", titleColor: "#fff", bodyColor: "#e3e7ef", padding: 10, cornerRadius: 6,
    callbacks: { label: (ctx) => ` ${t("{n} VMs ({p}%)", { n: ctx.raw, p: pct(ctx.raw) })}${links[ctx.dataIndex] ? " · " + t("clic para ver") : ""}` },
  };
  const onHover = (e, els) => { e.native.target.style.cursor = els.length && links[els[0].index] ? "pointer" : "default"; };
  const onClick = (e, els) => els.length && go(els[0].index);
  const el = document.getElementById("cv-" + c.id);

  if (c.kind === "bar") {
    instances.push(new Chart(el, {
      type: "bar",
      data: { labels, datasets: [{ data: values, backgroundColor: labels.map((l) => (isOther(l) ? OTHER : SERIES[0])),
        borderRadius: 4, borderSkipped: "start", maxBarThickness: 18, categoryPercentage: 0.8 }] },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: { duration: 300 }, onHover, onClick,
        plugins: { legend: { display: false }, tooltip },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: GRID }, border: { display: false } },
          y: { grid: { display: false }, ticks: { color: TEXT, autoSkip: false,
            callback(v) { const l = this.getLabelForValue(v); return l.length > 24 ? l.slice(0, 23) + "…" : l; } } },
        },
      },
    }));
    return;
  }

  const colors = colorsFor(c.id, labels);
  instances.push(new Chart(el, {
    type: c.kind,
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderColor: SURFACE, borderWidth: 2, hoverOffset: 6 }] },
    options: {
      maintainAspectRatio: false, cutout: c.kind === "doughnut" ? "60%" : 0, animation: { duration: 300 }, onHover, onClick,
      plugins: { legend: { display: false }, tooltip },
    },
  }));
  document.getElementById("lg-" + c.id).innerHTML = labels.map((l, i) => {
    const name = links[i] ? `<a href="${esc(links[i])}">${esc(l)}</a>` : esc(l);
    return `<li title="${esc(l)}"><span class="sw" style="background:${colors[i]}"></span><span class="lb">${name}</span>
      <span class="vl">${values[i]} · ${pct(values[i])}%</span></li>`;
  }).join("");
}

async function load() {
  const r = await api("/api/charts");
  version = r.version;
  charts = r.charts;
  render();
}

// Comprueba cada 5 s si el inventario cambió (escaneos, VMs nuevas, etiquetas...) y redibuja.
setInterval(async () => {
  if (document.hidden || editor.open) return;
  try {
    const r = await api("/api/charts/version");
    if (r.version !== version) load();
  } catch { /* servidor reiniciándose */ }
}, 5000);

// ---------- editor ----------

const form = document.getElementById("editor-form");
const F = (name) => form.elements[name];
const FILTER_KEYS = ["client", "environment", "tag", "os_family", "os_name"];
const pkgField = document.getElementById("pkg-field");
F("dimension").addEventListener("change", () => { pkgField.hidden = F("dimension").value !== "package_version"; });

function openEditor(id) {
  const c = charts.find((x) => x.id === id);
  document.getElementById("editor-title").textContent = c ? t("Editar gráfico") : t("Nuevo gráfico");
  F("id").value = c ? c.id : "";
  F("title").value = c ? c.title : "";
  form.querySelector(`input[name=kind][value=${c ? c.kind : "pie"}]`).checked = true;
  F("dimension").value = c ? c.dimension : "os";
  F("package").value = c ? c.package || "" : "";
  for (const f of FILTER_KEYS) { const v = c && c.filters[f]; setMulti("f_" + f, !v ? [] : Array.isArray(v) ? v : [v]); }
  pkgField.hidden = F("dimension").value !== "package_version";
  editor.showModal();
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (F("dimension").value === "package_version" && !F("package").value.trim()) { alert(t("Indica el paquete.")); return; }
  const body = {
    title: F("title").value, kind: form.querySelector("input[name=kind]:checked").value,
    dimension: F("dimension").value, package: F("package").value,
    filters: Object.fromEntries(FILTER_KEYS.map((f) => [f, multiValues("f_" + f)])),
  };
  await api(F("id").value ? `/api/charts/${F("id").value}` : "/api/charts", body);
  editor.close();
  load();
});

async function deleteChart(id) {
  if (!confirm(t("¿Eliminar este gráfico?"))) return;
  await api(`/api/charts/${id}`, { delete: true });
  load();
}

async function moveChart(id, move) {
  await api(`/api/charts/${id}`, { move });
  load();
}

load();
