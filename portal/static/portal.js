"use strict";
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const S = {
  session: null,
  tokens: [],
  selected: new Set(),
  detail: null,
  view: "tokens",
  step: 0,
  trace: [],
  busy: false,
  settings: null,
  logo: "",
  testResults: {},
};
const VIEWS = {
  tokens: ["My access tokens", "Manage the credentials your applications use."],
  activity: ["Activity", "Review token changes and who made them."],
  transcript: [
    "API transcript",
    "Inspect the Kubernetes requests for your most recent operation.",
  ],
  policies: [
    "Lifecycle policies",
    "Read the declarative policies installed for this portal.",
  ],
  settings: [
    "Portal settings",
    "Organisation, gateway connection and employee access.",
  ],
};
const STEPS = ["profile", "gateway", "auth", "behaviour"];
const date = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        day: "numeric",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";
function notify(message, error = false) {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
  $("notice").hidden = false;
  clearTimeout(S.timer);
  S.timer = setTimeout(() => ($("notice").hidden = true), error ? 10000 : 5000);
}
async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": S.session?.csrf || "",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new Error("Connection interrupted. Please retry.");
  }
  const data = await response.json();
  if (response.status === 401 && path !== "/api/session") {
    location.assign("/");
  }
  if (!response.ok || !data.ok)
    throw new Error(data.error || `Request failed (${response.status}).`);
  if (data.trace) {
    S.trace = data.trace;
    renderTrace();
  }
  return data;
}
function brand(profile) {
  $("company").textContent = profile.company;
  $("brand-title").textContent = profile.title;
  $("gate-title").textContent = profile.title;
  $("gate-copy").textContent = profile.subtitle;
  document.title = profile.title + " · " + profile.company;
  document.documentElement.style.setProperty("--accent", profile.accent);
  $("brand-logo").hidden = !profile.logo;
  $("brand-mark").hidden = !!profile.logo;
  if (profile.logo) $("brand-logo").src = profile.logo;
  else $("brand-logo").removeAttribute("src");
}
async function session() {
  S.session = await api("/api/session");
  brand(S.session.branding);
  const who = S.session.user;
  $("gate").hidden = !!who;
  $("shell").hidden = !who;
  $("identity").hidden = !who;
  if (!who) {
    $("bootstrap-form").hidden = S.session.configured;
    $("oidc-login").hidden = !S.session.configured;
    $("signin-title").textContent = S.session.configured
      ? "Employee sign-in"
      : "First-time setup";
    $("signin-copy").textContent = S.session.configured
      ? "Continue with your organisation’s identity provider."
      : "An administrator needs to configure this installation.";
    return;
  }
  const admin = who.role === "admin";
  $("identity-name").textContent = who.name;
  $("identity-role").textContent = who.bootstrap
    ? "Setup administrator"
    : who.role;
  $("nav-settings").hidden = !admin;
  $("nav-transcript").hidden = !admin && !S.session.features.userTranscript;
  $("nav-policies").hidden = !admin && !S.session.features.userPolicies;
  document.querySelector("[data-view=tokens]").textContent = admin
    ? "All tokens"
    : "My tokens";
  document.querySelectorAll("nav a:not(#nav-settings)").forEach((a) => {
    if (!S.session.configured) a.hidden = true;
  });
  navigate(
    S.session.configured ? location.hash.slice(1) || "tokens" : "settings",
  );
}
async function navigate(view) {
  if (!S.session?.user) return;
  if (!VIEWS[view]) view = "tokens";
  if (view === "settings" && S.session.user.role !== "admin") view = "tokens";
  if (
    (view === "transcript" && $("nav-transcript").hidden) ||
    (view === "policies" && $("nav-policies").hidden)
  )
    view = "tokens";
  S.view = view;
  document
    .querySelectorAll(".view")
    .forEach((el) => (el.hidden = el.id !== "view-" + view));
  document.querySelectorAll("[data-view]").forEach((el) => {
    el.classList.toggle("active", el.dataset.view === view);
    if (el.dataset.view === view) el.setAttribute("aria-current", "page");
    else el.removeAttribute("aria-current");
  });
  const admin = S.session.user.role === "admin";
  $("view-eyebrow").textContent = admin
    ? "PLATFORM ADMINISTRATION"
    : "EMPLOYEE ACCESS";
  $("view-title").textContent =
    view === "tokens" && admin
      ? "All access tokens"
      : !S.session.configured
        ? "Set up the access portal"
        : VIEWS[view][0];
  $("view-description").textContent = VIEWS[view][1];
  $("request-open").hidden = view !== "tokens" || !S.session.configured;
  try {
    if (view === "tokens") await loadTokens();
    if (view === "activity") await loadActivity();
    if (view === "policies") await loadPolicies();
    if (view === "settings" && !S.settings) await loadSettings();
  } catch (e) {
    notify(e.message, true);
  }
}
async function loadTokens() {
  if (S.loadingTokens) return;
  S.loadingTokens = true;
  try {
    const data = await api("/api/tokens");
    S.tokens = data.tokens;
    S.models = data.models;
    S.defaultExpiry = data.defaultExpiryMinutes;
    renderTokens();
    if (S.detail) renderDetail();
  } finally {
    S.loadingTokens = false;
  }
}
function filtered() {
  const query = $("search").value.trim().toLowerCase(),
    status = $("filter").value;
  return S.tokens.filter(
    (t) =>
      (!query ||
        [t.name, t.label, t.ownerName].some((v) =>
          String(v).toLowerCase().includes(query),
        )) &&
      (!status ||
        (status === "handover" ? !!t.pendingRotation : t.status === status)),
  );
}
function renderTokens() {
  const rows = filtered();
  S.selected = new Set(
    [...S.selected].filter((n) => rows.some((t) => t.name === n)),
  );
  const active = S.tokens.filter((t) => t.status === "active");
  $("stats").innerHTML = [
    ["Active tokens", active.length],
    ["Awaiting handover", active.filter((t) => t.pendingRotation).length],
    ["Expired tokens", S.tokens.filter((t) => t.status === "expired").length],
  ]
    .map(
      ([label, n]) =>
        `<div class="stat"><span>${label}</span><b>${n}</b></div>`,
    )
    .join("");
  $("token-rows").innerHTML = rows
    .map(
      (t) =>
        `<tr data-token="${esc(t.name)}"><td><input class="row-select" type="checkbox" aria-label="Select ${esc(t.label)}" ${S.selected.has(t.name) ? "checked" : ""}></td><td><button class="token-name" data-action="details">${esc(t.label)}</button><small>${esc(t.name)}</small></td><td>${esc(t.ownerName)}</td><td>${date(t.expiresAt)}</td><td><span class="status ${t.pendingRotation ? "handover" : esc(t.status)}">${t.pendingRotation ? "Handover" : esc(t.status)}</span></td><td><div class="row-actions"><button data-action="test">Test</button>${t.status === "active" ? `<button data-action="${t.pendingRotation ? "details" : "rotate"}">${t.pendingRotation ? "Handover" : "Rotate"}</button><button data-action="revoke">Revoke</button>` : ""}${t.status === "expired" ? '<button data-action="renew">Renew</button>' : ""}<button class="danger" data-action="delete">Delete</button></div></td></tr>`,
    )
    .join("");
  $("empty").hidden = rows.length > 0;
  $("empty").querySelector("h3").textContent = S.tokens.length
    ? "No matching tokens"
    : "No access tokens";
  $("token-rows")
    .querySelectorAll(".row-select")
    .forEach(
      (cb) =>
        (cb.onchange = () => {
          const n = cb.closest("tr").dataset.token;
          if (cb.checked) S.selected.add(n);
          else S.selected.delete(n);
          bulkState();
        }),
    );
  $("token-rows")
    .querySelectorAll("[data-action]")
    .forEach(
      (b) =>
        (b.onclick = () =>
          action(b.closest("tr").dataset.token, b.dataset.action)),
    );
  bulkState();
}
function bulkState() {
  $("bulk").hidden = !S.selected.size;
  $("bulk-count").textContent = S.selected.size + " selected";
  const count = filtered().length;
  $("select-all").checked = count > 0 && S.selected.size === count;
  $("select-all").indeterminate =
    S.selected.size > 0 && S.selected.size < count;
  $("select-all").disabled = !count;
}
function showValue(data) {
  $("token-value").textContent = data.raw;
  $("copy-token").textContent = "Copy token";
  $("value-note").textContent = data.pendingRotation
    ? "The original remains valid. Update your applications before completing the handover."
    : "Keep this value in your application’s secret store.";
  $("value-dialog").showModal();
}
function confirm(title, copy, label = "Continue") {
  $("confirm-title").textContent = title;
  $("confirm-copy").textContent = copy;
  $("confirm-yes").textContent = label;
  $("confirm-dialog").showModal();
  return new Promise((resolve) => (S.resolveConfirm = resolve));
}
function finishConfirm(value) {
  $("confirm-dialog").close();
  S.resolveConfirm?.(value);
  S.resolveConfirm = null;
}
async function action(name, op, extra = {}) {
  if (S.busy) return;
  const token = S.tokens.find((t) => t.name === name);
  if (!token) return;
  if (op === "details") {
    S.detail = name;
    S.detailSignature = null;
    renderDetail();
    $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const prompts = {
    rotate: [
      "Rotate " + token.label + "?",
      "Publish and verify a replacement. Keep the original until applications have migrated.",
      "Prepare replacement",
    ],
    renew: [
      "Renew " + token.label + "?",
      "Issue a fresh value with the current default expiry. Expired values remain invalid.",
      "Renew token",
    ],
    revoke: [
      "Revoke " + token.label + "?",
      "Withdraw every live generation. The lifecycle record remains available.",
      "Revoke token",
    ],
    delete: [
      "Delete " + token.label + "?",
      "Withdraw access and delete the token record and encrypted values. Activity events retain their configured Kubernetes retention.",
      "Delete token",
    ],
    complete: [
      "Have applications migrated?",
      "The portal rechecks the replacement, then retires overlapping generations.",
      "Confirm handover",
    ],
  };
  if (prompts[op] && !(await confirm(...prompts[op]))) return;
  S.busy = true;
  try {
    const data = await api(
      `/api/tokens/${encodeURIComponent(name)}/${op}`,
      op === "complete" ? { migrated: true } : extra,
    );
    if (data.raw) showValue(data);
    if (op === "test") {
      S.detail = name;
      S.detailSignature = null;
      renderDetail();
      $("test-result").hidden = false;
      $("test-result").textContent =
        `HTTP ${data.status} · ${data.status === 200 ? "Accepted" : data.status === 401 ? "Token rejected" : data.status === 429 ? "Budget exceeded" : "Request not accepted"} · ${data.ms} ms`;
      S.testResults[name] = "Last test · " + $("test-result").textContent;
      $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
    } else
      notify(
        op === "delete"
          ? "Token deleted."
          : op === "rotate"
            ? "Replacement ready for handover."
            : "Token updated.",
      );
    if (op === "delete" && S.detail === name) S.detail = null;
    S.detailSignature = null;
    await loadTokens();
  } catch (e) {
    notify(e.message, true);
  } finally {
    S.busy = false;
  }
}
function renderDetail() {
  const t = S.tokens.find((t) => t.name === S.detail);
  $("detail").hidden = !t;
  if (!t) return;
  const signature = JSON.stringify([
    t.name,
    t.status,
    t.pendingRotation,
    t.generations,
  ]);
  if (S.detailSignature === signature) return;
  S.detailSignature = signature;
  const oldResult = S.testResults[t.name] || "";
  $("detail").innerHTML =
    `<div class="card-heading"><div><span class="eyebrow">TOKEN DETAILS</span><h2>${esc(t.label)}</h2><small>${esc(t.name)} · ${esc(t.ownerName)}</small></div><button id="detail-close">Close</button></div><div class="metadata"><div><span>Status</span><b>${esc(t.status)}</b></div><div><span>Created</span><b>${date(t.createdAt)}</b></div><div><span>Expires</span><b>${date(t.expiresAt)}</b></div></div>${t.pendingRotation ? `<div class="handover"><h3>Replacement published. Original retained.</h3><p>Reveal the replacement, update your applications and verify their traffic before completing the handover.</p><button class="primary" id="complete-rotation">Applications migrated · complete rotation</button></div>` : ""}${t.status === "active" ? `<form id="detail-form"><div class="form-grid"><label>Application / purpose<input id="detail-label" value="${esc(t.label)}" maxlength="80" required></label><label>Extend expiry<select id="detail-expiry"><option value="0">Keep current expiry</option><option value="60">Extend by one hour</option><option value="1440">Extend by one day</option></select></label></div><fieldset><legend>Model permissions</legend><div class="model-options">${S.models.map((m) => `<label><input type="checkbox" value="${esc(m)}" ${t.models.includes(m) ? "checked" : ""}> ${esc(m)}</label>`).join("")}</div></fieldset><button class="primary" type="submit">Save changes</button> <button type="button" id="reveal-token">Reveal current token</button></form>` : ""}<div class="detail-grid"><div class="card"><h3>Token history</h3><div class="table-wrap"><table><thead><tr><th>Generation</th><th>Issued</th><th>Status</th><th></th></tr></thead><tbody>${t.generations.map((g, i) => `<tr><td>${i + 1}<small>${esc(g.id)}</small></td><td>${date(g.mintedAt)}</td><td><span class="status ${esc(g.status)}">${esc(g.status)}</span></td><td><button data-generation="${esc(g.id)}">Test</button></td></tr>`).join("")}</tbody></table></div></div><div class="card"><h3>Check token access</h3><p class="help">Send a request to the administrator-configured gateway test model.</p><button id="test-current">Run test</button><div class="result" id="test-result" ${oldResult ? "" : "hidden"}>${esc(oldResult)}</div></div></div>`;
  $("detail-close").onclick = () => {
    S.detail = null;
    $("detail").hidden = true;
  };
  if ($("complete-rotation"))
    $("complete-rotation").onclick = () => action(t.name, "complete");
  if ($("reveal-token"))
    $("reveal-token").onclick = () => action(t.name, "reveal");
  $("test-current").onclick = () => action(t.name, "test");
  $("detail")
    .querySelectorAll("[data-generation]")
    .forEach(
      (b) =>
        (b.onclick = () =>
          action(t.name, "test", { generation: b.dataset.generation })),
    );
  if ($("detail-form"))
    $("detail-form").onsubmit = async (e) => {
      e.preventDefault();
      await action(t.name, "update", {
        label: $("detail-label").value,
        models: [
          ...$("detail-form").querySelectorAll("input[type=checkbox]:checked"),
        ].map((i) => i.value),
        extendMinutes: +$("detail-expiry").value,
      });
    };
}
function renderTrace() {
  $("transcript").innerHTML = S.trace
    .map(
      (t) =>
        `<div class="trace-call"><b>${esc(t.method)} ${esc(t.path)}</b> <span class="badge">${t.status}</span>${t.body ? `<details><summary>Request body</summary><pre>${esc(JSON.stringify(t.body, null, 2))}</pre></details>` : ""}</div>`,
    )
    .join("");
}
async function loadActivity() {
  const data = await api("/api/activity");
  $("activity").innerHTML =
    data.events
      .map(
        (e) =>
          `<div class="activity-row"><time>${date(e.time)}</time><b>${esc(e.reason.replace(/([a-z])([A-Z])/g, "$1 $2"))}</b><span>${esc(e.message)}</span></div>`,
      )
      .join("") || '<p class="muted">No recent activity.</p>';
}
async function loadPolicies() {
  const data = await api("/api/policies");
  $("policies").innerHTML =
    data.mode === "external"
      ? "<p>Lifecycle reconciliation is managed externally. No portal-managed Kyverno policies are installed.</p>"
      : data.policies
          .map(
            (p) =>
              `<details class="policy-row"><summary>${esc(p.name)} <small>${esc(p.kind)}</small><span class="status ${p.ready ? "active" : "handover"}">${p.ready ? "Ready" : "Not ready"}</span></summary><pre>${esc(p.yaml)}</pre></details>`,
          )
          .join("") ||
        '<p class="error">No installed lifecycle policies were found. Check the Helm policy settings.</p>';
}
async function loadSettings() {
  const [data, discovery] = await Promise.all([
    api("/api/admin/settings"),
    api("/api/admin/gateways"),
  ]);
  S.settings = data.settings;
  S.settingsVersion = data.resourceVersion;
  S.gateways = discovery.gateways;
  S.logo = S.settings.branding.logo;
  const c = S.settings;
  for (const [id, value] of Object.entries({
    "company-input": c.branding.company,
    "title-input": c.branding.title,
    "subtitle-input": c.branding.subtitle,
    "accent-input": c.branding.accent,
    "test-url-input": c.gateway.testURL,
    "test-model-input": c.gateway.testModel,
    "models-input": c.lifecycle.models.join("\n"),
    "issuer-input": c.auth.issuer,
    "client-input": c.auth.clientId,
    "groups-claim-input": c.auth.groupsClaim,
    "admin-groups-input": c.auth.adminGroups.join("\n"),
    "user-groups-input": c.auth.userGroups.join("\n"),
    "expiry-input": c.lifecycle.defaultExpiryMinutes,
    "rotation-input": c.lifecycle.rotationMinutes,
    "quota-input": c.lifecycle.dailyTokenQuota,
  }))
    $(id).value = value;
  for (const [id, value] of Object.entries({
    "allow-authenticated-input": c.auth.allowAllAuthenticated,
    "auto-rotate-input": c.lifecycle.automaticRotation,
    "show-transcript-input": c.features.userTranscript,
    "show-policies-input": c.features.userPolicies,
  }))
    $(id).checked = value;
  $("gateway-input").innerHTML =
    '<option value="">Select a Gateway…</option>' +
    S.gateways
      .map(
        (gw, i) =>
          `<option value="${i}" ${gw.conflicts.length && data.manageGatewayPolicy ? "disabled" : ""}>${esc(gw.namespace + "/" + gw.name)} · ${esc(gw.edition)}${gw.conflicts.length ? " · existing API-key policy" : ""}</option>`,
      )
      .join("");
  const index = S.gateways.findIndex(
    (g) => g.namespace === c.gateway.namespace && g.name === c.gateway.name,
  );
  $("gateway-input").value = index < 0 ? "" : String(index);
  $("scope-text").textContent =
    "Helm allows discovery and gateway configuration in: " +
    data.namespaces.join(", ") +
    ". Change this scope through a Helm upgrade; the wizard cannot grant itself additional permissions.";
  $("permissions").innerHTML = data.permissions
    .map(
      (p) =>
        `<div class="permission"><span>${esc(p.verb + " " + p.resource + " in " + p.namespace)}</span><b class="${p.allowed ? "yes" : "no"}">${p.allowed ? "Allowed" : "Denied"}</b></div>`,
    )
    .join("");
  $("callback-url").textContent = location.origin + "/auth/callback";
  $("secret-status").textContent = S.session.clientSecretConfigured
    ? "An OIDC client secret is configured."
    : "No OIDC client secret is configured. Use a public PKCE client, or provide a Secret through Helm for a confidential client.";
  $("reconciler-info").textContent =
    data.reconciler === "kyverno"
      ? "Kyverno policies reconcile tokens. A Kubernetes CronJob triggers timed transitions every minute."
      : "External reconciliation is selected. Supply a controller implementing the documented AccessToken contract before issuing tokens.";
  previewProfile();
  setStep(0);
}
function previewProfile() {
  $("profile-preview-name").textContent = $("company-input").value;
  $("logo-preview").hidden = !S.logo;
  if (S.logo) $("logo-preview").src = S.logo;
  else $("logo-preview").removeAttribute("src");
}
function setStep(index) {
  S.step = Math.max(0, Math.min(3, index));
  document
    .querySelectorAll("[data-settings]")
    .forEach((el) => (el.hidden = el.dataset.settings !== STEPS[S.step]));
  document
    .querySelectorAll("[data-step]")
    .forEach((b) =>
      b.classList.toggle("active", b.dataset.step === STEPS[S.step]),
    );
  $("settings-back").hidden = S.step === 0;
  $("settings-next").hidden = S.step === 3;
  $("settings-save").hidden = S.step !== 3;
}
function collectSettings() {
  const list = (id) =>
    $(id)
      .value.split(/[\n,]/)
      .map((v) => v.trim())
      .filter(Boolean);
  const gw = S.gateways[+$("gateway-input").value];
  if ($("gateway-input").value === "" || !gw)
    throw new Error("Select a discovered Gateway.");
  return {
    ...S.settings,
    branding: {
      company: $("company-input").value,
      title: $("title-input").value,
      subtitle: $("subtitle-input").value,
      accent: $("accent-input").value,
      logo: S.logo,
    },
    gateway: {
      namespace: gw.namespace,
      name: gw.name,
      edition: gw.edition,
      testURL: $("test-url-input").value,
      testModel: $("test-model-input").value,
    },
    auth: {
      issuer: $("issuer-input").value.trim(),
      clientId: $("client-input").value.trim(),
      groupsClaim: $("groups-claim-input").value.trim(),
      adminGroups: list("admin-groups-input"),
      userGroups: list("user-groups-input"),
      allowAllAuthenticated: $("allow-authenticated-input").checked,
    },
    features: {
      userTranscript: $("show-transcript-input").checked,
      userPolicies: $("show-policies-input").checked,
    },
    lifecycle: {
      defaultExpiryMinutes: +$("expiry-input").value,
      rotationMinutes: +$("rotation-input").value,
      dailyTokenQuota: +$("quota-input").value,
      automaticRotation: $("auto-rotate-input").checked,
      models: list("models-input"),
    },
  };
}
async function bulk(actionName) {
  const names = [...S.selected];
  if (names.length > 25) {
    notify("Select up to 25 tokens per batch.", true);
    return;
  }
  if (
    !names.length ||
    !(await confirm(
      `${actionName === "delete" ? "Delete" : "Revoke"} ${names.length} tokens?`,
      "Each token is authorised and processed separately. Failures are reported per token.",
      "Confirm",
    ))
  )
    return;
  try {
    const data = await api("/api/bulk", { names, action: actionName });
    const failed = data.results.filter((r) => !r.ok);
    S.selected.clear();
    notify(
      `${data.results.length - failed.length} of ${data.results.length} completed.` +
        (failed.length ? " " + failed.map((r) => r.error).join("; ") : ""),
      failed.length > 0,
    );
    await loadTokens();
  } catch (e) {
    notify(e.message, true);
  }
}
function bind() {
  window.addEventListener("hashchange", () => navigate(location.hash.slice(1)));
  $("bootstrap-form").onsubmit = async (e) => {
    e.preventDefault();
    try {
      await api("/api/bootstrap", { token: $("bootstrap-token").value });
      $("bootstrap-token").value = "";
      await session();
    } catch (error) {
      $("gate-error").textContent = error.message;
    }
  };
  $("signout").onclick = async () => {
    await api("/api/logout", {});
    location.href = "/";
  };
  $("search").oninput = $("filter").onchange = renderTokens;
  $("refresh").onclick = () =>
    loadTokens().catch((e) => notify(e.message, true));
  $("select-all").onchange = (e) => {
    filtered().forEach((t) =>
      e.target.checked ? S.selected.add(t.name) : S.selected.delete(t.name),
    );
    renderTokens();
  };
  $("bulk-clear").onclick = () => {
    S.selected.clear();
    renderTokens();
  };
  $("bulk-delete").onclick = () => bulk("delete");
  $("bulk-revoke").onclick = () => bulk("revoke");
  $("request-open").onclick = () => {
    $("token-label").value = "";
    $("token-expiry").value = S.defaultExpiry;
    $("request-error").textContent = "";
    $("request-models").innerHTML = S.models
      .map(
        (m, i) =>
          `<label><input type="checkbox" value="${esc(m)}" ${i === 0 ? "checked" : ""}> ${esc(m)}</label>`,
      )
      .join("");
    $("request-dialog").showModal();
    $("token-label").focus();
  };
  $("request-form").onsubmit = async (e) => {
    e.preventDefault();
    $("token-create").disabled = true;
    try {
      const data = await api("/api/tokens", {
        label: $("token-label").value,
        ttlMinutes: +$("token-expiry").value,
        models: [...$("request-models").querySelectorAll("input:checked")].map(
          (i) => i.value,
        ),
      });
      $("request-dialog").close();
      showValue(data);
      S.detail = data.name;
      S.detailSignature = null;
      await loadTokens();
    } catch (error) {
      $("request-error").textContent = error.message;
    } finally {
      $("token-create").disabled = false;
    }
  };
  document
    .querySelectorAll("[data-close]")
    .forEach((b) => (b.onclick = () => $(b.dataset.close).close()));
  $("value-dialog").addEventListener(
    "close",
    () => ($("token-value").textContent = ""),
  );
  $("copy-token").onclick = async () => {
    try {
      await navigator.clipboard.writeText($("token-value").textContent);
      $("copy-token").textContent = "Copied ✓";
    } catch {
      notify("Select and copy the value manually.", true);
    }
  };
  $("confirm-cancel").onclick = () => finishConfirm(false);
  $("confirm-yes").onclick = () => finishConfirm(true);
  $("confirm-dialog").addEventListener("cancel", () => {
    S.resolveConfirm?.(false);
    S.resolveConfirm = null;
  });
  $("activity-refresh").onclick = () =>
    loadActivity().catch((e) => notify(e.message, true));
  $("policies-refresh").onclick = () =>
    loadPolicies().catch((e) => notify(e.message, true));
  document
    .querySelectorAll("[data-step]")
    .forEach((b) => (b.onclick = () => setStep(STEPS.indexOf(b.dataset.step))));
  $("settings-back").onclick = () => setStep(S.step - 1);
  $("settings-next").onclick = () => setStep(S.step + 1);
  $("company-input").oninput = previewProfile;
  $("gateway-input").onchange = () => {
    const gw = S.gateways[+$("gateway-input").value];
    if (gw && gw.testURL) $("test-url-input").value = gw.testURL;
  };
  $("remove-logo").onclick = () => {
    S.logo = "";
    $("logo-file").value = "";
    previewProfile();
  };
  $("profile-file").onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      if (file.size > 180000) throw new Error("Profile file is too large.");
      const data = await api(
        "/api/admin/profile",
        JSON.parse(await file.text()),
      );
      for (const [key, id] of Object.entries({
        company: "company-input",
        title: "title-input",
        subtitle: "subtitle-input",
        accent: "accent-input",
      }))
        $(id).value = data.branding[key];
      S.logo = data.branding.logo;
      previewProfile();
      notify("Profile imported. Save settings to apply it.");
    } catch (error) {
      notify(error.message, true);
    }
  };
  $("logo-file").onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      if (file.size > 131072)
        throw new Error("Logo must be smaller than 128 KB.");
      const reader = new FileReader();
      const logo = await new Promise((resolve, reject) => {
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
      const data = await api("/api/admin/profile", {
        ...S.settings.branding,
        logo,
      });
      S.logo = data.branding.logo;
      previewProfile();
    } catch (error) {
      notify(error.message, true);
    }
  };
  $("settings-form").onsubmit = async (e) => {
    e.preventDefault();
    $("settings-save").disabled = true;
    $("settings-status").textContent =
      "Checking identity and gateway configuration…";
    try {
      const candidate = collectSettings();
      const data = await api("/api/admin/settings", {
        settings: candidate,
        resourceVersion: S.settingsVersion,
      });
      S.settingsVersion = data.resourceVersion;
      S.settings = { ...candidate, configured: true };
      $("settings-status").textContent = "Settings saved.";
      if (data.signInRequired) {
        S.settings = null;
        await session();
        notify(
          "Setup complete. Sign in with your organisation’s identity provider.",
        );
      } else {
        await session();
        notify("Settings saved.");
      }
    } catch (error) {
      $("settings-status").textContent = error.message;
      notify(error.message, true);
    } finally {
      $("settings-save").disabled = false;
    }
  };
}
async function boot() {
  bind();
  try {
    await session();
  } catch (e) {
    notify(e.message, true);
    $("gate").hidden = false;
    $("gate-error").textContent = e.message;
  }
  setInterval(() => {
    if (
      S.session?.configured &&
      S.session.user &&
      S.view === "tokens" &&
      !S.busy &&
      !document.hidden &&
      !$("request-dialog").open &&
      !$("confirm-dialog").open
    )
      loadTokens().catch(() => {});
  }, 5000);
}
boot();
