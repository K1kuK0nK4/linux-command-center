// Safe mode: dialog to confirm a dangerous command by typing CONFIRM.
// Replaces prompt(), which truncates long texts. Used by Remote execution (app.js) and the terminal.
const CONFIRM_WORD = "CONFIRM";

function askDangerConfirm(reasons, command, title) {
  const tr = (s, vars) => (typeof t === "function" ? t(s, vars) : s);
  if (!document.getElementById("danger-style")) {
    const st = document.createElement("style");
    st.id = "danger-style";
    st.textContent = `
      .danger-dlg { max-width: min(720px, 92vw); width: 100%; border: 1px solid var(--bad, #f07163); border-radius: 10px;
        background: var(--panel, #1a1f29); color: var(--text, #e3e7ef); padding: 20px; box-sizing: border-box; }
      .danger-dlg::backdrop { background: rgba(0,0,0,.6); }
      .danger-dlg h2 { margin: 0 0 8px; font-size: 16px; color: var(--bad, #f07163); }
      .danger-dlg ul { margin: 6px 0 10px; padding-left: 20px; }
      .danger-dlg pre { max-height: 180px; overflow: auto; white-space: pre-wrap; word-break: break-all; margin: 0 0 12px;
        padding: 8px 10px; border-radius: 6px; background: var(--panel-2, #12151c); font: 12.5px Consolas, monospace; }
      .danger-dlg input { width: 100%; box-sizing: border-box; padding: 7px 9px; margin: 6px 0 14px; border-radius: 6px;
        border: 1px solid var(--border, #2d3443); background: var(--bg, #12151c); color: inherit; font: 14px Consolas, monospace; }
      .danger-dlg .btns { display: flex; gap: 8px; justify-content: flex-end; }
      .danger-dlg button { padding: 7px 14px; border-radius: 6px; border: 1px solid var(--border, #3a4459);
        background: var(--panel-2, #2a3245); color: inherit; font: inherit; cursor: pointer; }
      .danger-dlg button.go { background: var(--bad, #c0392b); border-color: var(--bad, #c0392b); color: #fff; }
      .danger-dlg button.go:disabled { opacity: .4; cursor: not-allowed; }`;
    document.head.appendChild(st);
  }
  const dlg = document.createElement("dialog");
  dlg.className = "danger-dlg";
  dlg.innerHTML = `<h2></h2><ul></ul><pre></pre><label></label><input autocomplete="off" spellcheck="false">
    <div class="btns"><button type="button" class="cancel"></button><button type="button" class="go" disabled></button></div>`;
  dlg.querySelector("h2").textContent = title || tr("SAFE MODE: this command may affect the servers:");
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = tr(r);
    dlg.querySelector("ul").appendChild(li);
  }
  dlg.querySelector("pre").textContent = command;
  dlg.querySelector("label").textContent = tr("If you really want to run it, type {w}:", { w: CONFIRM_WORD });
  dlg.querySelector(".cancel").textContent = tr("Cancel");
  dlg.querySelector(".go").textContent = tr("Run");
  document.body.appendChild(dlg);
  const input = dlg.querySelector("input"), go = dlg.querySelector(".go");
  input.addEventListener("input", () => { go.disabled = input.value.trim() !== CONFIRM_WORD; });
  return new Promise((resolve) => {
    const done = (ok) => { dlg.close(); dlg.remove(); resolve(ok); };
    go.onclick = () => done(true);
    dlg.querySelector(".cancel").onclick = () => done(false);
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); done(false); });   // Esc key
    input.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      // Consume the key: otherwise this same Enter reaches the terminal once the dialog closes
      e.preventDefault();
      e.stopPropagation();
      if (!go.disabled) done(true);
    });
    dlg.showModal();
    input.focus();
  });
}
