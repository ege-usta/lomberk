// Rowback panel. Agent SQL is untrusted: everything is rendered with textContent, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);
const REFRESH_MS = 10000;
const STATUS_WORD = {
  pending: "HELD", applied: "APPLIED", undone: "UNDONE", rejected: "REJECTED",
  denied: "DENIED", failed: "FAILED", approved: "RUNNING", executing: "RUNNING",
};
let required = 1;

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props || {});
  for (const c of children) node.append(c instanceof Node ? c : document.createTextNode(String(c ?? "")));
  return node;
}

async function call(path, method = "GET", body) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "X-Rowback-Panel": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "login") { showSignin(); throw new Error("Signed out."); }
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status}).`);
  return data;
}

function toast(text, bad) {
  const t = $("toast");
  t.textContent = text;
  t.className = bad ? "toast bad" : "toast";
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.textContent = ""; }, 6000);
}

function when(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function act(id, action, button) {
  if (action === "undo" && !confirm("Undo this write? Rowback restores the rows it changed, cascades included.")) return;
  button.disabled = true;
  try {
    const r = await call(`api/checkpoints/${encodeURIComponent(id)}/${action}`, "POST");
    const bad = !["applied", "undone", "rejected", "awaiting_approval"].includes(r.status);
    toast(r.message || r.status, bad);
  } catch (e) {
    toast(e.message, true);
  }
  await refresh();
}

// What the held write would change, from its dry run. Agent data: text nodes only.
function cellText(v) { return v === null || v === undefined ? "NULL" : typeof v === "object" ? JSON.stringify(v) : String(v); }

function previewBlock(p) {
  if (!p) return "";
  const tables = Object.entries(p.tables).map(([t, n]) => `${t} (${n})`).join(", ");
  const head = el("p", { className: "meta" }, `Would change ${p.rows} row${p.rows === 1 ? "" : "s"}: ${tables}`
    + (p.truncated ? ` · first ${p.sample.length} shown` : "") + " · dry run when held");
  const rows = p.sample.map((s) => {
    const detail = s.changes
      ? Object.entries(s.changes).map(([c, [a, b]]) => `${c}: ${cellText(a)} → ${cellText(b)}`).join("; ")
      : Object.entries(s.row || {}).map(([c, v]) => `${c}=${cellText(v)}`).join(", ");
    return el("tr", {},
      el("td", {}, el("span", { className: `op ${s.op}` }, s.op.toUpperCase())),
      el("td", {}, s.table),
      el("td", { className: "nowrap" }, Object.values(s.key || {}).join(", ")),
      el("td", {}, el("code", {}, detail)));
  });
  return el("div", { className: "preview" }, head,
    el("div", { className: "scroll" }, el("table", {}, el("tbody", {}, ...rows))));
}

function pendingItem(cp) {
  const approve = el("button", { className: "btn allow", type: "button" }, "Approve");
  const reject = el("button", { className: "btn deny", type: "button" }, "Reject");
  approve.onclick = () => act(cp.public_id, "approve", approve);
  reject.onclick = () => act(cp.public_id, "reject", reject);
  const got = cp.approved_by.length;  // the server decides the quorum; this only lists who approved
  const meta = el("p", { className: "meta" },
    el("span", { className: "verdict held" }, "HELD"), ` ${cp.agent_label || "agent"} · ${when(cp.created_at)} · ${cp.public_id}`);
  const count = required > 1
    ? el("p", { className: "meta" }, got ? `Approved so far by ${cp.approved_by.join(", ")}` : "No approvals yet")
    : "";
  return el("li", {}, meta, el("pre", { className: "sql" }, cp.sql_text), previewBlock(cp.preview), count,
    el("div", { className: "actions" }, approve, reject));
}

function historyRow(cp) {
  const word = STATUS_WORD[cp.status] || cp.status.toUpperCase();
  let cell = "";
  if (cp.status === "applied" && cp.classification !== "READ") {
    const undo = el("button", { className: "btn small", type: "button" }, "Undo");
    undo.onclick = () => act(cp.public_id, "undo", undo);
    cell = undo;
  }
  return el("tr", {},
    el("td", { className: "nowrap" }, when(cp.created_at)),
    el("td", {}, el("span", { className: `verdict ${cp.status}` }, word)),
    el("td", {}, cp.agent_label || ""),
    el("td", {}, el("code", { className: "sql-line", title: cp.sql_text }, cp.sql_text)),
    el("td", {}, cp.approved_by.join(", ")),
    el("td", { className: "num" }, cp.rows_affected ?? ""),
    el("td", {}, cell));
}

async function refresh() {
  let data;
  try { data = await call("api/checkpoints"); } catch (e) { if (e.message !== "Signed out.") toast(e.message, true); return; }
  const pending = data.items.filter((c) => c.status === "pending");
  $("pending").replaceChildren(...pending.map(pendingItem));
  $("empty").hidden = pending.length > 0;
  $("history").replaceChildren(...data.items.filter((c) => c.status !== "pending").map(historyRow));
}

function showSignin() {
  $("app").hidden = true;
  $("signin").hidden = false;
  $("logout").hidden = true;
  $("who").textContent = "";
}

async function start() {
  const s = await call("api/session");
  required = s.required_approvals;
  $("rule").textContent = required > 1 ? `Each write needs ${required} different people signed in with the same SSO or Slack.` : "";
  if (!s.actor) {
    showSignin();
    $("sso").hidden = !s.sso;
    $("keyform").hidden = !s.admin_key;
    if (!s.sso && !s.admin_key) $("signin-error").textContent = "No sign-in method is configured.";
    return;
  }
  $("signin").hidden = true;
  $("app").hidden = false;
  $("logout").hidden = false;
  $("who").textContent = s.actor === "api_admin" ? "admin key" : s.actor.replace(/^oidc:/, "");
  await refresh();
  if (!start.timer) start.timer = setInterval(refresh, REFRESH_MS);
}

$("keyform").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("signin-error").textContent = "";
  try {
    await call("login", "POST", { key: $("key").value });
    $("key").value = "";
    await start();
  } catch (err) {
    $("signin-error").textContent = err.message;
  }
});

$("logout").addEventListener("click", async () => {
  await call("logout", "POST").catch(() => {});
  location.reload();
});

start().catch((e) => { $("signin-error").textContent = e.message; showSignin(); });
