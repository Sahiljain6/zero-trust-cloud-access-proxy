(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const form = $("#request-form"), deviceSelect = $("#device-id"), secretInput = $("#device-secret");
  const payloadInput = $("#payload"), tamperInput = $("#tamper"), submitButton = $("#send-request");
  const formError = $("#form-error"), decisionPill = $("#decision-pill"), checkList = $("#check-list");
  const emptyTrace = $("#empty-trace"), resultMessage = $("#result-message"), previewWrap = $("#payload-preview-wrap");
  const payloadPreview = $("#payload-preview"), devicesList = $("#device-list"), auditList = $("#audit-list");
  const adminMessage = $("#admin-message"), encoder = new TextEncoder();
  function encodeBase64(text) {
    const bytes = encoder.encode(text); let binary = "";
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function hex(buffer) {
    return Array.from(new Uint8Array(buffer), (v) => v.toString(16).padStart(2, "0")).join("");
  }
  async function signRequest(deviceId, timestamp, nonce, payloadB64, secret) {
    if (!window.crypto || !window.crypto.subtle) throw new Error("Web Crypto is unavailable. Open on localhost or over HTTPS.");
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
    const canonical = "v1\n" + deviceId + "\n" + timestamp + "\n" + nonce + "\n" + payloadB64;
    return hex(await crypto.subtle.sign("HMAC", key, encoder.encode(canonical)));
  }
  const safeText = (v) => String(v == null ? "" : v);
  function showError(message) { formError.textContent = message; formError.hidden = false; }
  function clearError() { formError.textContent = ""; formError.hidden = true; }
  function addText(parent, tag, cls, value) {
    const el = document.createElement(tag); if (cls) el.className = cls;
    el.textContent = safeText(value); parent.append(el); return el;
  }
  function renderChecks(checks) {
    checkList.replaceChildren();
    for (const check of checks || []) {
      const row = document.createElement("li"); row.className = "check-row";
      const passed = check.status === "passed";
      const symbol = addText(row, "span", "check-symbol" + (passed ? "" : " failed"), passed ? "✓" : "×");
      symbol.setAttribute("aria-hidden", "true");
      const copy = document.createElement("span"); copy.className = "check-copy";
      addText(copy, "strong", "", check.name); addText(copy, "small", "", check.detail);
      const status = addText(row, "span", "check-status" + (passed ? "" : " failed"), passed ? "PASSED" : "FAILED");
      row.append(copy, status); checkList.append(row);
    }
    emptyTrace.hidden = true; checkList.hidden = false;
  }
  function renderDecision(result, httpOk) {
    const allowed = httpOk && result.decision === "ALLOW";
    decisionPill.className = "pill " + (allowed ? "pill-allow" : "pill-deny");
    decisionPill.textContent = allowed ? "ACCESS ALLOWED" : "ACCESS DENIED";
    renderChecks(result.checks || []);
    resultMessage.className = "result-message " + (allowed ? "allow" : "deny");
    resultMessage.textContent = result.message || "The policy engine returned no message.";
    resultMessage.hidden = false; previewWrap.hidden = !allowed || !result.payload_preview;
    payloadPreview.textContent = result.payload_preview || "";
  }
  async function loadDevices() {
    try {
      const response = await fetch("/api/devices", {headers:{Accept:"application/json"}});
      if (!response.ok) throw new Error("Could not load device registry.");
      const result = await response.json(), current = deviceSelect.value;
      deviceSelect.replaceChildren(); devicesList.replaceChildren();
      const active = (result.devices || []).filter((d) => d.status === "active");
      if (active.length === 0) {
        const option = document.createElement("option"); option.value = ""; option.textContent = "No active configured devices"; deviceSelect.append(option);
      } else {
        for (const d of active) {
          const option = document.createElement("option"); option.value = d.device_id;
          option.textContent = d.display_name + " (" + d.device_id + ")"; deviceSelect.append(option);
        }
        if (active.some((d) => d.device_id === current)) deviceSelect.value = current;
      }
      if (!result.devices || result.devices.length === 0) addText(devicesList, "p", "muted", "No devices are configured on the server.");
      for (const d of result.devices || []) {
        const card = document.createElement("div"); card.className = "device-card";
        const info = document.createElement("div"); info.className = "device-info";
        addText(info, "strong", "", d.device_id); addText(info, "small", "", d.display_name);
        const actions = document.createElement("div"); actions.className = "device-actions";
        const enabled = d.status === "active";
        const state = document.createElement("span"); state.className = "state-label" + (enabled ? "" : " disabled");
        const dot = document.createElement("span"); dot.className = "state-dot" + (enabled ? "" : " disabled");
        state.append(dot, document.createTextNode(enabled ? "ACTIVE" : "DISABLED"));
        const toggle = document.createElement("button"); toggle.type = "button"; toggle.className = "mini-button";
        toggle.textContent = enabled ? "Disable" : "Enable"; toggle.dataset.deviceId = d.device_id; toggle.dataset.nextActive = enabled ? "false" : "true";
        toggle.setAttribute("aria-label", (enabled ? "Disable " : "Enable ") + d.device_id);
        toggle.addEventListener("click", manageDevice); actions.append(state, toggle); card.append(info, actions); devicesList.append(card);
      }
    } catch (error) { devicesList.replaceChildren(); addText(devicesList, "p", "muted", error.message || "Device registry unavailable."); }
  }
  async function loadAudit() {
    try {
      const response = await fetch("/api/audit", {headers:{Accept:"application/json"}});
      if (!response.ok) throw new Error("Could not load audit log.");
      const result = await response.json(); auditList.replaceChildren();
      if (!result.events || result.events.length === 0) { addText(auditList, "p", "muted", "No events recorded yet. Run a request to create the first event."); return; }
      for (const e of result.events) {
        const card = document.createElement("div"); card.className = "audit-event";
        const top = document.createElement("div"); top.className = "audit-top";
        const decisionClass = e.decision === "ALLOW" ? "allow" : e.decision === "ADMIN" ? "admin" : "deny";
        addText(top, "span", "audit-decision " + decisionClass, e.decision); addText(top, "span", "audit-time", e.created_at);
        addText(card, "strong", "", e.device_id || "Unidentified request"); addText(card, "p", "", e.reason);
        card.prepend(top); auditList.append(card);
      }
    } catch (error) { auditList.replaceChildren(); addText(auditList, "p", "muted", error.message || "Audit log unavailable."); }
  }
  async function manageDevice(event) {
    const button = event.currentTarget, token = $("#admin-token").value;
    if (!token) { adminMessage.textContent = "Enter the admin token to change device state."; return; }
    button.disabled = true;
    try {
      const response = await fetch("/api/devices/" + encodeURIComponent(button.dataset.deviceId), {
        method:"PATCH", headers:{"Content-Type":"application/json", Accept:"application/json", "X-Admin-Token":token},
        body:JSON.stringify({active:button.dataset.nextActive === "true"})
      });
      const result = await response.json(); adminMessage.textContent = result.message || "Device update complete.";
      if (!response.ok) throw new Error(result.message || "Device update failed.");
      await Promise.all([loadDevices(), loadAudit()]);
    } catch (error) { adminMessage.textContent = error.message || "Device update failed."; }
    finally { button.disabled = false; }
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); clearError();
    const deviceId = deviceSelect.value, secret = secretInput.value, payload = payloadInput.value;
    if (!deviceId) return showError("Choose a configured and active device.");
    if (secret.length < 24) return showError("Enter this device's configured key (at least 24 characters).");
    if (!payload.trim()) return showError("Enter a non-empty payload.");
    if (encoder.encode(payload).length > 8192) return showError("Payload exceeds the 8192-byte limit.");
    submitButton.disabled = true; submitButton.querySelector("span").textContent = "Signing and verifying…";
    decisionPill.className = "pill"; decisionPill.textContent = "CHECKS IN PROGRESS";
    emptyTrace.hidden = false; checkList.hidden = true; resultMessage.hidden = true; previewWrap.hidden = true;
    try {
      const timestamp = Math.floor(Date.now() / 1000);
      const random = crypto.getRandomValues(new Uint8Array(24));
      const nonce = Array.from(random, (v) => v.toString(16).padStart(2, "0")).join("");
      const payloadB64 = encodeBase64(payload);
      const signature = await signRequest(deviceId, timestamp, nonce, payloadB64, secret);
      const envelope = {device_id:deviceId, timestamp:timestamp, nonce:nonce, payload_b64:payloadB64, signature:signature};
      if (tamperInput.checked) envelope.payload_b64 = (envelope.payload_b64[0] === "A" ? "B" : "A") + envelope.payload_b64.slice(1);
      const response = await fetch("/api/verify", {method:"POST", headers:{"Content-Type":"application/json", Accept:"application/json"}, body:JSON.stringify(envelope)});
      const result = await response.json(); renderDecision(result, response.ok);
      if (!response.ok && result.message) showError(result.message);
      await loadAudit(); await loadDevices();
    } catch (error) { showError(error.message || "Could not complete the request."); }
    finally { submitButton.disabled = false; submitButton.querySelector("span").textContent = "Run zero-trust checks"; }
  });
  function updateCount() { $("#payload-count").textContent = encoder.encode(payloadInput.value).length + " / 8192 bytes"; }
  payloadInput.addEventListener("input", updateCount);
  $("#refresh-devices").addEventListener("click", loadDevices);
  $("#refresh-audit").addEventListener("click", loadAudit);
  async function checkHealth() {
    const text = $("#service-status"), light = $(".status-light");
    try {
      const response = await fetch("/api/health", {headers:{Accept:"application/json"}});
      if (!response.ok) throw new Error("Service unavailable");
      text.textContent = "Policy engine online"; light.classList.add("online");
    } catch (_error) { text.textContent = "Service unavailable"; }
  }
  updateCount(); Promise.all([checkHealth(), loadDevices(), loadAudit()]);
})();
