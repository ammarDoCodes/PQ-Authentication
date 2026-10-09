const signInPanel = document.querySelector("#sign-in");
const workspace = document.querySelector("#workspace");
const account = document.querySelector("#account");
const notice = document.querySelector("#notice");
const tenantData = document.querySelector("#tenant-data");
let csrfToken = "";
let tenantID = "";
let selectedApplicationID = "";
let selectedApplicationName = "";
let policyProfiles = [];
let policyItems = [];

function showMessage(message, isError = true) {
  notice.textContent = message;
  notice.classList.toggle("is-error", isError);
  notice.classList.toggle("is-success", !isError);
}

async function readProblem(response) {
  try {
    const body = await response.json();
    return body.detail || body.title || `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (tenantID) headers.set("X-QG-Tenant-ID", tenantID);
  if (options.method && options.method !== "GET") {
    headers.set("X-QG-CSRF-Token", csrfToken);
    if (path.startsWith("/v1/")) headers.set("Idempotency-Key", crypto.randomUUID());
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  if (!response.ok) throw new Error(await readProblem(response));
  if (response.status === 204) return null;
  return response.json();
}

function addAction(container, label, action, quiet = true) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button${quiet ? " button-quiet" : ""}`;
  button.textContent = label;
  button.addEventListener("click", action);
  container.append(button);
  return button;
}

function renderProfileOptions() {
  const mode = document.querySelector("#policy-mode").value;
  const select = document.querySelector("#policy-profile");
  select.replaceChildren();
  for (const profile of policyProfiles.filter((item) => mode === "observe-only" || item.mode === mode)) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = `${profile.id} · ${profile.provider_version}`;
    select.append(option);
  }
  select.disabled = select.options.length === 0;
}

async function loadPolicies(applicationID, applicationName) {
  selectedApplicationID = applicationID;
  selectedApplicationName = applicationName;
  const workspace = document.querySelector("#policy-workspace");
  workspace.hidden = false;
  document.querySelector("#policy-application-name").textContent = applicationName;
  showMessage("Loading policy revisions…", false);
  try {
    const response = await api(`/v1/applications/${encodeURIComponent(applicationID)}/policies?limit=100`);
    policyItems = response.items || [];
    renderPolicies();
    showMessage("Policy revisions loaded.", false);
  } catch (error) {
    policyItems = [];
    renderPolicies();
    showMessage(error.message);
  }
}

async function loadPosture(applicationID, applicationName) {
  selectedApplicationID = applicationID;
  selectedApplicationName = applicationName;
  const panel = document.querySelector("#posture-workspace");
  const summary = document.querySelector("#posture-summary");
  const observations = document.querySelector("#posture-observations");
  panel.hidden = false;
  document.querySelector("#posture-application-name").textContent = applicationName;
  summary.replaceChildren();
  observations.replaceChildren();
  showMessage("Loading posture snapshot…", false);
  try {
    const [posture, recent] = await Promise.all([
      api(`/v1/applications/${encodeURIComponent(applicationID)}/posture`),
      api(`/v1/applications/${encodeURIComponent(applicationID)}/observations?limit=10`),
    ]);
    addTextItem(summary, posture.assessment_status.replaceAll("_", " "), (posture.reason_codes || []).join(" · ") || "No reported blockers", `as of ${new Date(posture.as_of).toLocaleString()}`);
    const policy = posture.active_policy;
    addTextItem(summary, "Policy", policy ? `Revision ${policy.revision} · ${policy.mode || "mode unavailable"} · ${policy.integrity}` : "No active policy", policy ? `${policy.active_exceptions} active exceptions` : "Create and activate a policy revision.");
    addTextItem(summary, "Identity adapters", `${posture.identity_adapters.active} active`, `${posture.identity_adapters.verification_required} need verification`);
    addTextItem(summary, "Key references", `${posture.keys.active} active`, `${posture.keys.rotation_due} rotation due · ${posture.keys.expired} expired`);
    addTextItem(summary, "Migration observations", `${posture.observations.count} recorded`, `${posture.observations.open_blockers} open blockers`);
    addTextItem(summary, "Integration status", "Inventory only", (posture.next_actions || []).join(" "));
    for (const item of recent.items || []) {
      addTextItem(observations, item.blocker || item.algorithm_profile, `${item.source} · ${item.protocol}`, `${item.confidence} · ${new Date(item.observed_at).toLocaleString()}`);
    }
    if (!recent.items?.length) addEmpty(observations, "No observations have been recorded.");
    showMessage("Posture snapshot loaded.", false);
  } catch (error) {
    addEmpty(summary, error.message);
    showMessage(error.message);
  }
}

function renderPolicies() {
  const container = document.querySelector("#policy-list");
  container.replaceChildren();
  if (!policyItems.length) addEmpty(container, "No policy revisions yet. Create a draft below.");
  const active = policyItems.find((item) => item.state === "active");
  for (const policy of policyItems) {
    const item = addTextItem(container, `Revision ${policy.revision} · ${policy.state}`, `${policy.document.mode} · ${policy.document.allowed_profiles.join(", ")}`, `Updated ${new Date(policy.lifecycle_updated_at).toLocaleString()}`);
    const actions = document.createElement("div");
    actions.className = "policy-actions";
    if (policy.state === "draft" || policy.state === "scheduled" || policy.state === "active") {
      addAction(actions, "Simulate sample", async () => {
        const rule = policy.document.route_rules[0];
        const method = rule?.method || "GET";
        const path = `${rule?.path_prefix || "/"}example`;
        const profileID = rule?.allowed_profiles?.[0] || policy.document.allowed_profiles[0];
        const identityACR = policy.document.identity_requirements.required_acrs[0] || "";
        try {
          const result = await api(`/v1/policies/${encodeURIComponent(policy.id)}/simulate`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ method, path, profile_id: profileID, identity_acr: identityACR }),
          });
          showMessage(`Simulation: ${result.decision} · ${(result.reason_codes || []).join(", ")}`, false);
        } catch (error) { showMessage(error.message); }
      });
    }
    if (policy.state === "draft" || policy.state === "scheduled") {
      addAction(actions, "Activate now", async () => {
        try {
          await api(`/v1/policies/${encodeURIComponent(policy.id)}/activate`, { method: "POST", headers: { "If-Match": policy.etag } });
          await loadPolicies(selectedApplicationID, selectedApplicationName);
        } catch (error) { showMessage(error.message); }
      }, false);
    }
    if (policy.state === "draft") {
      addAction(actions, "Schedule", async () => {
        const localTime = document.querySelector("#policy-schedule-time").value;
        const effectiveAt = new Date(localTime);
        if (!localTime || Number.isNaN(effectiveAt.valueOf())) {
          showMessage("Choose a valid activation time.");
          return;
        }
        try {
          await api(`/v1/policies/${encodeURIComponent(policy.id)}/schedule`, {
            method: "POST", headers: { "Content-Type": "application/json", "If-Match": policy.etag },
            body: JSON.stringify({ effective_at: effectiveAt.toISOString() }),
          });
          await loadPolicies(selectedApplicationID, selectedApplicationName);
        } catch (error) { showMessage(error.message); }
      });
    }
    if (policy.state !== "retired") {
      addAction(actions, "Retire", async () => {
        try {
          await api(`/v1/policies/${encodeURIComponent(policy.id)}/retire`, { method: "POST", headers: { "If-Match": policy.etag } });
          await loadPolicies(selectedApplicationID, selectedApplicationName);
        } catch (error) { showMessage(error.message); }
      });
    } else if (active) {
      addAction(actions, "Roll back to this", async () => {
        try {
          await api(`/v1/policies/${encodeURIComponent(active.id)}/rollback`, {
            method: "POST", headers: { "Content-Type": "application/json", "If-Match": active.etag },
            body: JSON.stringify({ target_revision_id: policy.id, reason_code: "ROLLBACK_COMPATIBILITY" }),
          });
          await loadPolicies(selectedApplicationID, selectedApplicationName);
        } catch (error) { showMessage(error.message); }
      }, false);
    }
    if (actions.childElementCount) item.append(actions);
  }
}

function addTextItem(container, title, detail, secondary = "") {
  const item = document.createElement("article");
  item.className = "item";
  const heading = document.createElement("strong");
  heading.textContent = title;
  item.append(heading);
  const line = document.createElement("span");
  line.textContent = detail;
  item.append(line);
  if (secondary) {
    const extra = document.createElement("span");
    extra.textContent = ` · ${secondary}`;
    item.append(extra);
  }
  container.append(item);
  return item;
}

function addEmpty(container, message) {
  const empty = document.createElement("p");
  empty.className = "empty";
  empty.textContent = message;
  container.append(empty);
}

async function refreshTenant() {
  const normalized = document.querySelector("#tenant-id").value.trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalized)) {
    showMessage("Enter a valid tenant ID.");
    return;
  }
  if (tenantID && tenantID !== normalized) {
    selectedApplicationID = "";
    selectedApplicationName = "";
    policyItems = [];
    document.querySelector("#policy-workspace").hidden = true;
    document.querySelector("#posture-workspace").hidden = true;
  }
  tenantID = normalized;
  showMessage("Loading tenant workspace…", false);
  try {
    const [tenant, apps, events, registry] = await Promise.all([
      api(`/v1/tenants/${encodeURIComponent(tenantID)}`),
      api(`/v1/tenants/${encodeURIComponent(tenantID)}/applications?limit=50`),
      api(`/v1/tenants/${encodeURIComponent(tenantID)}/audit-events?limit=50`),
      api(`/v1/tenants/${encodeURIComponent(tenantID)}/algorithm-profiles`),
    ]);
    policyProfiles = registry.profiles || [];
    renderProfileOptions();
    document.querySelector("#tenant-name").textContent = `${tenant.display_name} · ${tenant.id}`;
    document.querySelector("#tenant-heading").textContent = "Tenant workspace";
    const applications = document.querySelector("#applications");
    const auditEvents = document.querySelector("#audit-events");
    applications.replaceChildren();
    auditEvents.replaceChildren();
    for (const application of apps.items || []) {
      const item = addTextItem(applications, application.display_name, application.external_id, `${application.status} · ${application.integration_mode}`);
      const policies = document.createElement("button");
      policies.type = "button";
      policies.className = "button button-quiet item-action";
      policies.textContent = "View policies";
      policies.addEventListener("click", () => loadPolicies(application.id, application.display_name));
      item.append(policies);
      const posture = document.createElement("button");
      posture.type = "button";
      posture.className = "button button-quiet item-action";
      posture.textContent = "View posture";
      posture.addEventListener("click", () => loadPosture(application.id, application.display_name));
      item.append(posture);
      const disable = document.createElement("button");
      disable.type = "button";
      disable.className = "button button-quiet item-action";
      disable.textContent = "Disable application";
      disable.addEventListener("click", async () => {
        if (!window.confirm(`Disable ${application.display_name}?`)) return;
        try {
          await api(`/v1/applications/${encodeURIComponent(application.id)}/disable`, {
            method: "POST", headers: { "If-Match": application.etag },
          });
          await refreshTenant();
          showMessage("Application disabled.", false);
        } catch (error) { showMessage(error.message); }
      });
      item.append(disable);
    }
    if (!apps.items?.length) addEmpty(applications, "No applications are registered yet.");
    for (const event of events.items || []) {
      addTextItem(auditEvents, event.action, `${event.outcome} · ${event.target_type}`, new Date(event.occurred_at).toLocaleString());
    }
    if (!events.items?.length) addEmpty(auditEvents, "No audit events are available.");
    tenantData.hidden = false;
    showMessage("Tenant workspace loaded.", false);
    document.querySelector("#request-id").textContent = `Request ${tenant.request_id || apps.request_id || events.request_id || ""}`;
    if (selectedApplicationID && (apps.items || []).some((application) => application.id === selectedApplicationID)) {
      await loadPolicies(selectedApplicationID, selectedApplicationName);
    }
  } catch (error) {
    tenantData.hidden = true;
    showMessage(error.message);
  }
}

document.querySelector("#tenant-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await refreshTenant();
});

document.querySelector("#environment-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const environmentForm = event.currentTarget;
  try {
    const form = new FormData(environmentForm);
    const environment = await api(`/v1/tenants/${encodeURIComponent(tenantID)}/environments`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: form.get("name"), lifecycle: form.get("lifecycle") }),
    });
    document.querySelector("#environment-id").value = environment.id;
    environmentForm.reset();
    showMessage(`Environment created. ID: ${environment.id}`, false);
  } catch (error) { showMessage(error.message); }
});

document.querySelector("#application-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const applicationForm = event.currentTarget;
  try {
    const form = new FormData(applicationForm);
    await api(`/v1/tenants/${encodeURIComponent(tenantID)}/applications`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        environment_id: form.get("environment_id"), external_id: form.get("external_id"),
        display_name: form.get("display_name"), integration_mode: form.get("integration_mode"),
      }),
    });
    applicationForm.reset();
    await refreshTenant();
    showMessage("Application registered.", false);
  } catch (error) { showMessage(error.message); }
});

document.querySelector("#policy-mode").addEventListener("change", renderProfileOptions);

document.querySelector("#policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const policyForm = event.currentTarget;
  if (!selectedApplicationID) {
    showMessage("Choose an application's policies first.");
    return;
  }
  try {
    const form = new FormData(policyForm);
    const acr = String(form.get("required_acr") || "").trim();
    const profileID = String(form.get("profile") || "");
    const pathPrefix = String(form.get("path_prefix") || "").trim();
    const document = {
      mode: String(form.get("mode")),
      allowed_profiles: [profileID],
      fallback: String(form.get("fallback")),
      stale_behavior: String(form.get("stale_behavior")),
      route_rules: [{ method: String(form.get("method")), path_prefix: pathPrefix, allowed_profiles: [profileID] }],
      identity_requirements: { required_acrs: acr ? [acr] : [] },
      exceptions: [],
      effective_window: { starts_at: null, ends_at: null },
    };
    await api(`/v1/applications/${encodeURIComponent(selectedApplicationID)}/policies`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(document),
    });
    policyForm.reset();
    renderProfileOptions();
    await loadPolicies(selectedApplicationID, selectedApplicationName);
  } catch (error) { showMessage(error.message); }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    await api("/auth/logout", { method: "POST" });
    window.location.reload();
  } catch (error) { showMessage(error.message); }
});

async function initialize() {
  try {
    const session = await api("/auth/session");
    if (!session.authenticated) return;
    csrfToken = session.csrf_token;
    signInPanel.hidden = true;
    workspace.hidden = false;
    account.hidden = false;
    document.querySelector("#session-label").textContent = `Signed in · ${new Date(session.auth_time).toLocaleString()}`;
    showMessage("Enter the tenant ID provided by your administrator.", false);
  } catch (error) {
    showMessage(error.message);
  }
}

initialize();
