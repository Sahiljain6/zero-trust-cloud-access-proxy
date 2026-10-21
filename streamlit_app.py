"""Streamlit entry point for the Zero-Trust Cloud Access Proxy demo."""
import base64
import json
import os
import time
from datetime import datetime

import streamlit as st
st.set_page_config(page_title="Zero-Trust Cloud Access Proxy", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
from dotenv import load_dotenv

load_dotenv()

SECRET_KEYS = (
    "APP_ENV", "FLASK_SECRET_KEY", "ADMIN_TOKEN", "DEVICE_SECRETS_JSON",
    "DATABASE_PATH", "REQUEST_TTL_SECONDS", "MAX_PAYLOAD_BYTES",
)

def load_deployment_secrets():
    try:
        values = dict(st.secrets)
    except Exception:
        values = {}
    for key in SECRET_KEYS:
        if key in values:
            value = values[key]
            if key == "DEVICE_SECRETS_JSON" and isinstance(value, dict):
                value = json.dumps(dict(value))
            elif not isinstance(value, str):
                value = str(value)
            os.environ[key] = value
    return values

DEPLOYMENT_SECRETS = load_deployment_secrets()

from ztproxy import create_app
from ztproxy.security import sign_request

st.markdown("""
<style>
.stApp{background:radial-gradient(ellipse at 7% -15%,rgba(112,173,104,.14),transparent 35rem),radial-gradient(ellipse at 95% 12%,rgba(68,125,99,.09),transparent 32rem),#080d0b}
[data-testid="stHeader"]{background:rgba(8,13,11,.75)}
[data-testid="stSidebar"]{background:#0b120e;border-right:1px solid #27372e}
.block-container{max-width:1500px;padding-top:1.8rem;padding-bottom:3rem}
h1,h2,h3{letter-spacing:-.035em}
.eyebrow{color:#b3ff6d;font-family:ui-monospace,monospace;letter-spacing:.14em;font-size:.72rem;text-transform:uppercase}
.hero{font-size:clamp(2.25rem,4vw,3.65rem);line-height:1.06;letter-spacing:-.055em;font-weight:720}
.hero em{color:#b3ff6d;font-style:normal}
.subtle{color:#9caf9f;line-height:1.8}
div[data-testid="stMetric"]{background:rgba(16,24,21,.82);border:1px solid #27372e;padding:1rem;border-radius:12px}
div[data-testid="stMetricLabel"] p{color:#91a396;font-size:.72rem}
div[data-testid="stMetricValue"]{color:#e9f2eb}
div[data-testid="stForm"]{background:rgba(16,24,21,.72);border:1px solid #27372e;border-radius:13px;padding:1.2rem}
.scope-note{border:1px solid rgba(255,210,124,.3);background:rgba(255,210,124,.05);border-radius:10px;padding:.9rem 1rem;color:#d6cfb5;line-height:1.65;font-size:.85rem}
.check-pass{color:#b3ff6d;font-weight:650}.check-fail{color:#ff7979;font-weight:650}.footnote{color:#77887d;font-size:.8rem}
hr{border-color:#27372e}
button[kind="primary"]{background:#b3ff6d!important;color:#0b1509!important;border:0!important}
button[kind="primary"]:hover{background:#c9ff9e!important}
@media(max-width:700px){.block-container{padding:1rem .8rem 2rem}}
</style>
""", unsafe_allow_html=True)

@st.cache_resource(show_spinner="Loading the policy engine…")
def get_policy_app():
    return create_app()

try:
    policy_app = get_policy_app()
except Exception as exc:
    st.error("The policy engine could not start. Check the app's Secrets configuration.")
    st.code(str(exc))
    st.stop()

def api(method, path, **kwargs):
    """Invoke the existing Flask routes in-process; no second web server."""
    with policy_app.test_client() as client:
        response = getattr(client, method.lower())(path, **kwargs)
        try:
            body = response.get_json()
        except Exception:
            body = None
        return response.status_code, body or {}

def new_signed_envelope(device_id, payload):
    """Create a demonstration client envelope with this device's configured test key."""
    secret = policy_app.config["DEVICE_SECRETS"].get(device_id, "unknown-device-test-secret-not-configured")
    timestamp = int(time.time())
    nonce = os.urandom(24).hex()
    payload_b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    signature = sign_request(device_id, timestamp, nonce, payload_b64, secret)
    return {"device_id": device_id, "timestamp": timestamp, "nonce": nonce, "payload_b64": payload_b64, "signature": signature}

def render_checks(checks):
    for item in checks or []:
        passed = item.get("status") == "passed"
        with st.container(border=True):
            left, right = st.columns([0.08, 0.92])
            left.markdown("### " + ("✓" if passed else "×"))
            right.markdown("**" + item.get("name", "Policy check") + "**")
            right.caption(item.get("detail", ""))
            right.markdown('<span class="' + ("check-pass" if passed else "check-fail") + '">' + ("PASSED" if passed else "FAILED") + "</span>", unsafe_allow_html=True)

def refresh_overview():
    _, device_data = api("get", "/api/devices")
    _, audit_data = api("get", "/api/audit")
    return device_data.get("devices", []), audit_data.get("events", [])

def fmt_time(value):
    try:
        return datetime.fromisoformat(value).strftime("%d %b %Y, %H:%M:%S")
    except (TypeError, ValueError):
        return str(value or "")

st.markdown('<p class="eyebrow">DEVICE IDENTITY · REQUEST INTEGRITY · REPLAY DEFENCE</p>', unsafe_allow_html=True)
st.markdown('<div class="hero">Trust is not assumed.<br><em>Every request is checked.</em></div>', unsafe_allow_html=True)
st.markdown('<p class="subtle">A zero-trust request-verification web application for the Cryptography and Network Security microproject. Inspect device policy, freshness, HMAC-SHA256 integrity, and replay protection in one trace.</p>', unsafe_allow_html=True)
st.markdown('<div class="scope-note"><strong>Implementation boundary:</strong> this Streamlit deployment runs the client simulator and the verification engine in one Python process. It demonstrates the verification pipeline, but is not a real isolated client/server trust boundary. EAP/802.1X or RADIUS is not connected; no live cloud resource is contacted; and no post-quantum algorithm is implemented.</div>', unsafe_allow_html=True)
st.write("")

devices, events = refresh_overview()
configured_keys = policy_app.config["DEVICE_SECRETS"]
admin_configured = ("ADMIN_TOKEN" in DEPLOYMENT_SECRETS) or (bool(os.environ.get("ADMIN_TOKEN")) and os.environ.get("ADMIN_TOKEN") != "local-admin-token-change-this-value")
active_count = sum(1 for item in devices if item.get("status") == "active" and item.get("device_id") in configured_keys)
allow_count = sum(1 for item in events if item.get("decision") == "ALLOW")
deny_count = sum(1 for item in events if item.get("decision") == "DENY")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Configured active devices", active_count)
m2.metric("Audit events retained", len(events))
m3.metric("Allowed decisions", allow_count)
m4.metric("Denied decisions", deny_count)

sim_tab, devices_tab, audit_tab, architecture_tab = st.tabs(["Request Simulator", "Device Registry", "Audit Trail", "Architecture & API"])

with sim_tab:
    request_col, info_col = st.columns([1.2, 0.8], gap="large")
    with request_col:
        st.subheader("01 / Build a signed request")
        all_options = [item["device_id"] for item in devices if item.get("device_id") in configured_keys]
        if "rogue_device_01" not in all_options:
            all_options.append("rogue_device_01")
        if not all_options:
            all_options = ["rogue_device_01"]
        preferred = "device_node_01" if "device_node_01" in all_options else all_options[0]
        default_index = all_options.index(preferred)
        with st.form("request_form", clear_on_submit=False):
            selected_device = st.selectbox("Simulated device", options=all_options, index=default_index, format_func=lambda value: value + (" — unknown device" if value not in configured_keys else " — " + ("active" if any(d["device_id"] == value and d["status"] == "active" for d in devices) else "disabled")))
            payload = st.text_area("Payload", value="Requesting secure confidential cloud database container.", max_chars=8192, height=130)
            tamper = st.checkbox("Simulate man-in-the-middle tampering", help="The request is signed, then its payload is modified before verification.")
            submitted = st.form_submit_button("Run zero-trust checks", type="primary", use_container_width=True)
        replay_clicked = st.button("Replay the last signed request", disabled=not bool(st.session_state.get("last_envelope")), use_container_width=True)
        if submitted:
            if not payload.strip():
                st.session_state["last_result"] = {"http_status":400,"body":{"decision":"DENY","message":"Payload must not be empty.","checks":[{"name":"Input validation","status":"failed","detail":"Payload must not be empty."}]}}
                st.session_state.pop("last_envelope", None)
            else:
                envelope = new_signed_envelope(selected_device, payload)
                if tamper and envelope["payload_b64"]:
                    original = envelope["payload_b64"]
                    envelope["payload_b64"] = ("A" if original[0] != "A" else "B") + original[1:]
                st.session_state["last_envelope"] = envelope
                code, body = api("post", "/api/verify", json=envelope)
                st.session_state["last_result"] = {"http_status":code,"body":body}
                st.session_state["last_request_summary"] = {"device_id":selected_device,"created_at":datetime.now().isoformat(timespec="seconds"),"tampered":tamper}
                st.rerun()
        if replay_clicked and st.session_state.get("last_envelope"):
            code, body = api("post", "/api/verify", json=st.session_state["last_envelope"])
            st.session_state["last_result"] = {"http_status":code,"body":body}
            st.session_state["last_request_summary"] = {**st.session_state.get("last_request_summary", {}),"replayed":True,"created_at":datetime.now().isoformat(timespec="seconds")}
            st.rerun()
    with info_col:
        st.subheader("02 / Policy controls")
        controls = [
            ("01","Input validation","JSON fields, payload encoding, request-size limits"),
            ("02","Device authorization","Device must exist, be active, and have a key"),
            ("03","Freshness","Timestamp must be inside the configured time window"),
            ("04","Payload integrity","Recomputed HMAC compared in constant time"),
            ("05","Replay protection","Device nonce can be accepted only once"),
        ]
        for number, title, detail in controls:
            with st.container(border=True):
                st.markdown("**" + number + " / " + title + "**")
                st.caption(detail)
        st.caption("SQLite retains device state, recent nonces, and up to 1,000 audit events.")
    result_data = st.session_state.get("last_result")
    if result_data:
        st.divider()
        body = result_data.get("body", {})
        allowed = body.get("decision") == "ALLOW" and result_data.get("http_status") == 200
        st.success("ACCESS ALLOWED") if allowed else st.error("ACCESS DENIED")
        st.markdown("#### Verification trace")
        render_checks(body.get("checks", []))
        st.info(body.get("message", "No response detail available."))
        if allowed and body.get("payload_preview"):
            st.markdown("**Accepted payload preview**")
            st.code(body["payload_preview"], language="text")
        summary = st.session_state.get("last_request_summary", {})
        if summary:
            st.caption("Device: " + str(summary.get("device_id", "unknown")) + " · Updated: " + fmt_time(summary.get("created_at")) + (" · Tamper test" if summary.get("tampered") else "") + (" · Replay attempt" if summary.get("replayed") else ""))

with devices_tab:
    st.subheader("03 / Device Registry")
    st.write("Device state is stored in SQLite. This demo can change state only for devices with a configured server-side key.")
    if not devices:
        st.info("No device keys are configured.")
    for device in devices:
        device_id = device["device_id"]
        is_active = device.get("status") == "active" and device_id in configured_keys
        left, middle, right = st.columns([2.1, 1, 1.2])
        left.markdown("**" + device.get("display_name", device_id) + "**")
        left.caption(device_id)
        middle.markdown("🟢 Active" if is_active else "🔴 Disabled")
        if admin_configured:
            with right:
                with st.form("device_" + device_id):
                    desired = st.form_submit_button("Disable" if is_active else "Enable", use_container_width=True)
                if desired:
                    token = st.session_state.get("admin_token", "")
                    code, body = api("patch", "/api/devices/" + device_id, headers={"X-Admin-Token":token}, json={"active":not is_active})
                    if code == 200:
                        st.success(body.get("message", "Device state updated."))
                        st.rerun()
                    else:
                        st.error(body.get("message", "Device state update failed."))
        else:
            right.caption("Admin token not configured")
        st.divider()
    if admin_configured:
        st.text_input("Admin token for this session", type="password", key="admin_token", help="Set ADMIN_TOKEN in Streamlit Secrets; enter the same value here to manage devices.")
    else:
        st.warning("Device state changes are disabled because ADMIN_TOKEN is not configured in Streamlit Secrets or the local environment.")

with audit_tab:
    st.subheader("04 / Security Audit Trail")
    st.caption("Audit records contain decision reasons and device IDs, not payloads, keys, or signatures.")
    if events:
        rows = [{"Time (UTC)":e.get("created_at",""),"Decision":e.get("decision",""),"Device":e.get("device_id") or "Unknown","Request ID":e.get("request_id",""),"Reason":e.get("reason","")} for e in events]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        if st.button("Refresh audit trail"):
            st.rerun()
    else:
        st.info("No audit events yet. Run a request to populate the audit trail.")

with architecture_tab:
    st.subheader("Request flow")
    st.code("Streamlit client simulator\n    │  Build sample request + HMAC-SHA256 signature\n    ▼\nInput validation ──► Device authorization\n    │                       │\n    ▼                       ▼\nTimestamp freshness ──► HMAC integrity validation\n    │                       │\n    └──────────┬────────────┘\n               ▼\n       SQLite nonce / replay check\n               │\n        ┌──────┴──────┐\n        ▼             ▼\n      DENY        ALLOW (local demo)\n        └──────┬──────┘\n               ▼\n          Audit trail", language="text")
    st.markdown("**Endpoints in the reused policy layer**")
    st.table([
        {"Method":"GET","Path":"/api/health","Purpose":"Service health"},
        {"Method":"GET","Path":"/api/devices","Purpose":"Read device registry; never returns keys"},
        {"Method":"POST","Path":"/api/verify","Purpose":"Validate signed request envelope"},
        {"Method":"GET","Path":"/api/audit","Purpose":"Read recent audit events"},
        {"Method":"PATCH","Path":"/api/devices/{device_id}","Purpose":"Admin-token-protected device state"},
    ])
    st.warning("These Flask routes are invoked internally inside Streamlit; they are not exposed as independent public HTTP endpoints.")

st.divider()
st.markdown('<p class="footnote">Educational CNS microproject · Sahil Rajkumar Jain and Dhruv Gada · HMAC-SHA256 provides message integrity/authentication relative to a shared key, not encryption. Streamlit Community Cloud may reset local files on restart; use managed persistent storage for long-term audit history.</p>', unsafe_allow_html=True)
