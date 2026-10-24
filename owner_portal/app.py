"""Local Streamlit owner-onboarding prototype (NOT for Community Cloud)."""
from __future__ import annotations

import json
from urllib import error, request

import streamlit as st

API = "http://127.0.0.1:8002"
st.set_page_config(page_title="CyberSentinel | Owner Onboarding", page_icon="🛡️", layout="wide")


def call(method: str, path: str, body: dict | None = None, authenticated: bool = True) -> dict:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if authenticated and st.session_state.get("owner_token"):
        headers["Authorization"] = "Bearer " + st.session_state["owner_token"]
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = request.Request(API + path, data=data, headers=headers, method=method)
    opener = request.build_opener(request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=8) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail", "Unexpected API error")
        except (ValueError, UnicodeDecodeError):
            detail = "Unexpected API error"
        raise RuntimeError(f"API {exc.code}: {detail}") from None
    except (error.URLError, TimeoutError) as exc:
        raise RuntimeError("Cannot connect to the local Owner API on port 8002") from exc



@st.fragment(run_every="10s")
def show_alerts(domain_id: str) -> None:
    st.markdown("#### Local detection alerts")
    st.caption("Auto-refreshes every 10 seconds while this page is open. Advisory signals, not confirmed attacks.")
    if st.button("Refresh alerts", key="refresh-alerts-" + domain_id):
        st.rerun()
    try:
        alerts = call("GET", f"/owner/domains/{domain_id}/alerts?limit=50")
    except RuntimeError as exc:
        st.error(str(exc))
        alerts = {"alerts": [], "total_alerts": 0}
    st.metric("Rule alerts", alerts["total_alerts"])
    for entry in alerts["alerts"]:
        with st.expander(f"{entry['severity'].upper()}: {entry['title']} - {entry['status']}"):
            st.write(entry["explanation"])
            st.write(f"Rule: `{entry['rule_id']}`")
            st.write(f"Count: {entry['observed_count']} / {entry['threshold_count']}")
            st.write(f"60-second window start: {entry['window_start']} (Unix UTC)")
            st.write(f"Pseudonymous source: `{entry['source_ref'][:8]}...`")
            if entry["status"] == "open":
                if st.button("Acknowledge", key="ack-" + entry["id"]):
                    try:
                        call("POST", f"/owner/domains/{domain_id}/alerts/{entry['id']}/acknowledge")
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))


st.title("🛡️ CyberSentinel - Owner Onboarding")
st.caption("LOCAL DEVELOPMENT ONLY · Owner accounts and DNS TXT verification · Local rule-based alerts; not a hosted 24/7 service")
st.info("This portal is intentionally separate from the public Streamlit demo. Do not deploy it on Streamlit Community Cloud.")
try:
    health = call("GET", "/owner/health", authenticated=False)
    if not health.get("mode") == "local-owner-onboarding":
        st.error("Unexpected backend mode")
        st.stop()
except RuntimeError as exc:
    st.error(str(exc))
    st.code("uvicorn owner_api.main:app --host 127.0.0.1 --port 8002", language="bash")
    st.stop()

if not st.session_state.get("owner_token"):
    left, right = st.columns(2, gap="large")
    with left:
        st.subheader("Create local account")
        with st.form("register"):
            reg_email = st.text_input("Email", key="reg_email")
            reg_password = st.text_input("Password (12-128 characters)", type="password", key="reg_password")
            reg_submit = st.form_submit_button("Register")
        if reg_submit:
            try:
                call("POST", "/owner/register", {"email": reg_email, "password": reg_password}, authenticated=False)
                st.success("Local account created. Sign in using the form on the right.")
            except RuntimeError as exc:
                st.error(str(exc))
    with right:
        st.subheader("Sign in")
        with st.form("login"):
            email = st.text_input("Email address", key="login_email")
            password = st.text_input("Password", type="password", key="login_password")
            submit = st.form_submit_button("Sign in")
        if submit:
            try:
                result = call("POST", "/owner/login", {"email": email, "password": password}, authenticated=False)
                st.session_state["owner_token"] = result["access_token"]
                st.rerun()
            except RuntimeError as exc:
                st.error(str(exc))
    st.stop()

try:
    me = call("GET", "/owner/me")
except RuntimeError as exc:
    st.error(str(exc))
    st.session_state.pop("owner_token", None)
    st.stop()

head, action = st.columns([5, 1])
head.success(f"Signed in: {me['email']}")
if action.button("Sign out"):
    try:
        call("POST", "/owner/logout")
    except RuntimeError:
        pass
    st.session_state.pop("owner_token", None)
    st.rerun()

st.subheader("Add a domain")
with st.form("new_domain"):
    domain = st.text_input("Public DNS hostname", placeholder="your-owned-domain.com")
    add = st.form_submit_button("Generate ownership challenge")
if add:
    try:
        claim = call("POST", "/owner/domains", {"domain": domain})
        st.session_state["pending_claim"] = claim
        st.success("Challenge generated. Add the DNS TXT record shown below.")
    except RuntimeError as exc:
        st.error(str(exc))

pending = st.session_state.get("pending_claim")
if pending:
    st.markdown("#### DNS TXT challenge (shown only when generated)")
    st.code(pending["txt_name"], language="text")
    st.code(pending["txt_value"], language="text")
    st.caption("TXT name above, TXT value below. Expires 24 hours after generation. Do not mistake this for a TLS certificate challenge.")

st.subheader("Your domains")
try:
    owned = call("GET", "/owner/domains")["domains"]
except RuntimeError as exc:
    st.error(str(exc))
    st.stop()
if not owned:
    st.info("No domains yet. Add a domain you administer.")
else:
    for item in owned:
        with st.container(border=True):
            st.write(f"**{item['domain']}** - {'✅ Verified' if item['verified'] else '⏳ Pending DNS proof'}")
            if not item["verified"]:
                a, b, c = st.columns(3)
                if a.button("Verify DNS", key="verify-" + item["id"]):
                    try:
                        result = call("POST", f"/owner/domains/{item['id']}/verify")
                        st.success("Domain control confirmed using DNS TXT" if result["verified"] else "Pending")
                        st.rerun()
                    except RuntimeError as exc:
                        st.warning(str(exc))
                if b.button("Rotate challenge", key="rotate-" + item["id"]):
                    try:
                        st.session_state["pending_claim"] = call("POST", f"/owner/domains/{item['id']}/rotate-challenge")
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))
                if c.button("Remove claim", key="remove-" + item["id"]):
                    try:
                        call("DELETE", f"/owner/domains/{item['id']}")
                        st.session_state.pop("pending_claim", None)
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))
            else:
                st.markdown("#### Local telemetry agent")
                st.caption("Step 11 uses owner-scoped API keys and local-only ingestion. It is not hosted 24/7.")
                try:
                    active_keys = call("GET", f"/owner/domains/{item['id']}/agent-keys")["keys"]
                    history = call("GET", f"/owner/domains/{item['id']}/telemetry")
                except RuntimeError as exc:
                    st.error(str(exc))
                    active_keys = []
                    history = {"events": [], "total_events": 0}
                with st.form("key-" + item["id"]):
                    key_label = st.text_input("Agent label", value="local-nginx", key="label-" + item["id"])
                    issued = st.form_submit_button("Generate agent API key")
                if issued:
                    try:
                        st.session_state["issued_agent_key"] = call("POST", f"/owner/domains/{item['id']}/agent-keys", {"label": key_label})
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))
                issued_key = st.session_state.get("issued_agent_key")
                if issued_key and issued_key["domain_id"] == item["id"]:
                    st.warning("Copy this agent key now. It will not be displayed by the API again. Do not share screenshots containing it.")
                    st.code(issued_key["agent_key"], language="text")
                    st.code("export CYBERSENTINEL_AGENT_KEY='<paste-agent-key-here>'", language="bash")
                    st.code(f"python -m cybersentinel_agent.cli --input simulations/runtime/logs/access.log --domain-id {item['id']}", language="bash")
                    st.caption("Step 13 optional: run a continuous localhost log follower with a durable outbox.")
                    st.code(
                        "cybersentinel-agent-watch --input simulations/runtime/logs/access.log "
                        "--state simulations/runtime/owner/nginx_watcher.sqlite3 "
                        f"--domain-id {item['id']} --poll-seconds 1", language="bash"
                    )
                    if st.button("Hide generated agent key", key="hide-key-" + item["id"]):
                        st.session_state.pop("issued_agent_key", None)
                        st.rerun()
                for agent_key in active_keys:
                    a, b = st.columns([4, 1])
                    a.write(f"Agent: `{agent_key['label']}`")
                    if b.button("Revoke", key="revoke-key-" + agent_key["id"]):
                        try:
                            call("DELETE", f"/owner/domains/{item['id']}/agent-keys/{agent_key['id']}")
                            st.rerun()
                        except RuntimeError as exc:
                            st.error(str(exc))
                st.metric("Received telemetry events", history["total_events"])
                if history["events"]:
                    st.dataframe(history["events"], hide_index=True, use_container_width=True)
                    st.caption("Pseudonymous per-day source references, no raw IPs or request URLs.")
                show_alerts(item["id"])
                if st.button("Revoke claim", key="revoke-" + item["id"]):
                    try:
                        call("DELETE", f"/owner/domains/{item['id']}")
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))

st.divider()
st.caption("Local rule alerts do not provide production-grade monitoring or verified attack detection. Domain DNS proof is not a guarantee of legal ownership.")
