"""CyberSentinel offline experiment explorer.

Launch: streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
The app intentionally does not deserialize model files or transmit local logs.
"""
from __future__ import annotations

import json
import os
from urllib import error, parse, request

import pandas as pd
import streamlit as st

st.set_page_config(page_title="CyberSentinel | Security Lab", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
.block-container {padding-top: 1.7rem; max-width: 1500px;}
[data-testid='stSidebar'] {background: #101b2b;}
[data-testid='stSidebar'] * {color: #f3f7ff !important;}
div[data-testid='stMetric'] {background: #111c2c; padding: 18px 20px; border: 1px solid #304457; border-radius: 12px;}
.hero {padding:22px 24px; border-radius:16px; border:1px solid #304457;
background:linear-gradient(105deg, #14283a 0%, #101927 100%); margin-bottom:18px;}
.hero h1 {color:#f0f8ff; margin:0; font-weight:700; font-size:30px;}
.hero p {color:#b8d4df; margin:8px 0 0;}
.section-note {color:#8ca2ae; font-size:13px;}
</style>
""", unsafe_allow_html=True)

BASE_URL = os.getenv("CYBERSENTINEL_API_URL", "http://127.0.0.1:8001").rstrip("/")
url_info = parse.urlsplit(BASE_URL)
if url_info.scheme != "http" or url_info.hostname not in ("localhost", "127.0.0.1", "::1") or url_info.path or url_info.query:
    st.error("CYBERSENTINEL_API_URL must be a plain localhost HTTP origin.")
    st.stop()


@st.cache_data(ttl=20, show_spinner=False)
def load_api(path: str):
    opener = request.build_opener(request.ProxyHandler({}))
    req = request.Request(BASE_URL + path, headers={"Accept": "application/json"})
    try:
        with opener.open(req, timeout=6) as response:
            return json.load(response)
    except (error.URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Cannot read local API ({path}): {exc}") from exc


def endpoint(run: str, name: str, **params: object) -> str:
    suffix = "/api/runs/" + parse.quote(run, safe="") + "/" + name
    return suffix + ("?" + parse.urlencode(params) if params else "")


def fmt_metric(value, digits: int = 2):
    if value is None:
        return "N/A"
    return f"{100*float(value):.{digits}f}%"


with st.sidebar:
    st.markdown("### 🛡️ CyberSentinel")
    st.caption("Security telemetry / research lab")
    st.markdown("---")
    st.info("OFFLINE SIMULATION ONLY — no live monitoring or production detection.")
    if st.button("↻ Refresh local results", use_container_width=True):
        load_api.clear()
        st.rerun()

try:
    health = load_api("/api/health")
    run_list = load_api("/api/runs").get("runs", [])
except RuntimeError as exc:
    st.error(str(exc))
    st.code("uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8001", language="bash")
    st.stop()

if health.get("mode") != "offline-local-simulation":
    st.error("Unexpected API mode; refusing to display this data.")
    st.stop()

if not run_list:
    st.warning("No Step 5 experiment was found. Generate lab data and train the model before opening the dashboard.")
    st.code("python -m scripts.run_lab_experiments --runs-per-class 40 --seed 42", language="bash")
    st.stop()

with st.sidebar:
    names = [item["run_id"] for item in run_list]
    selected = st.selectbox("Experiment run", names, index=0)
    selected_meta = next(x for x in run_list if x["run_id"] == selected)
    view = st.radio("Navigate", ["Overview", "Traffic Explorer", "Model Evaluation", "Robustness"], label_visibility="visible")
    st.markdown("---")
    st.caption("Source IPs may be simulated and client-supplied; never treat them as verified identities.")

try:
    summary = load_api(endpoint(selected, "summary"))
except RuntimeError as exc:
    st.error(str(exc))
    st.stop()

st.markdown("""<div class='hero'><h1>CyberSentinel / Experiment Explorer</h1>
<p>Read-only security telemetry analytics • Controlled localhost traffic • Not a production intrusion detection system</p></div>""", unsafe_allow_html=True)
st.caption(f"EXPERIMENT  /  {selected}     •     API status: {health.get('status', 'unknown')}     •     Mode: offline")

if view == "Overview":
    cols = st.columns(4)
    cols[0].metric("Simulated requests", f"{summary.get('simulation_requests', 0):,}")
    cols[1].metric("Labeled requests", f"{summary.get('matched_labeled_events', 0):,}")
    cols[2].metric("Window records", f"{summary.get('windows', 0):,}")
    cols[3].metric("Manifest gaps", f"{summary.get('manifest_records_without_event', 0):,}")
    st.markdown("### Traffic composition")
    c1,c2 = st.columns([2,1], gap="large")
    with c1:
        cnt = summary.get("window_label_counts", {})
        plot = pd.DataFrame({"scenario": list(cnt), "windows": list(cnt.values())}).set_index("scenario")
        if not plot.empty: st.bar_chart(plot, y="windows", color="#48b8b2")
    with c2:
        st.markdown("**Experiment details**")
        st.write(f"Seed: `{summary.get('seed')}`")
        st.write(f"Runs per class: `{summary.get('runs_per_class')}`")
        st.write(f"Window duration: `{summary.get('window_seconds')}` seconds")
        st.write(f"Unlabeled historical events excluded: `{summary.get('unlabeled_events')}`")
        st.caption("Simulation labels describe the replay plan, not confirmed malicious activity on a real network.")
    st.markdown("### Included features")
    st.write(", ".join(summary.get("model_feature_columns", [])))

elif view == "Traffic Explorer":
    scenario_options = ["All", "simulated_benign", "simulated_brute_force", "simulated_path_scan", "simulated_mixed_attack"]
    scenario = st.selectbox("Scenario filter", scenario_options)
    qs = {"limit":1000}
    if scenario != "All": qs["scenario"] = scenario
    try:
        win = load_api(endpoint(selected, "windows", **qs))
    except RuntimeError as exc:
        st.error(str(exc)); st.stop()
    df = pd.DataFrame(win.get("rows", []))
    st.caption(f"Showing {len(df)} windows out of {win.get('total_windows', 0)} (max 1,000). No model IDs or scenario labels are fed into the detector.")
    if df.empty:
        st.info("No windows for this scenario.")
    else:
        a,b = st.columns(2)
        with a:
            st.markdown("**Request count by scenario**")
            st.bar_chart(df.groupby("scenario_label")["request_count"].sum(), color="#53bdb0")
        with b:
            st.markdown("**Failed logins by scenario**")
            st.bar_chart(df.groupby("scenario_label")["failed_login_count"].sum(), color="#f59e72")
        st.markdown("**Traffic windows**")
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Download displayed windows (CSV)", df.to_csv(index=False), file_name="cybersentinel_windows_view.csv", mime="text/csv")

elif view == "Model Evaluation":
    if not selected_meta.get("has_metrics"):
        st.info("No ML metrics for this experiment. Run scripts.train_detector first.")
        st.stop()
    try:
        metrics = load_api(endpoint(selected, "metrics"))
        preds = load_api(endpoint(selected, "predictions", partition="test", limit=1000))
    except RuntimeError as exc:
        st.error(str(exc)); st.stop()
    splits = metrics.get("splits", {})
    partition = st.radio("Evaluation partition", ["test", "validation"], horizontal=True)
    section = splits.get(partition, {})
    i_f = section.get("isolation_forest", {})
    baseline = section.get("fixed_rule_baseline", {})
    columns = st.columns(4)
    columns[0].metric("Isolation Forest F1", fmt_metric(i_f.get("f1")))
    columns[1].metric("Isolation Forest recall", fmt_metric(i_f.get("recall")))
    columns[2].metric("Isolation Forest FPR", fmt_metric(i_f.get("false_positive_rate")))
    columns[3].metric("Average precision", fmt_metric(i_f.get("average_precision")))
    st.markdown("### Detector comparison")
    bar = pd.DataFrame({
        "Metric": ["Precision", "Recall", "F1"],
        "Isolation Forest": [i_f.get(x, 0) for x in ("precision","recall","f1")],
        "Fixed rule": [baseline.get(x, 0) for x in ("precision","recall","f1")],
    }).set_index("Metric")
    st.bar_chart(bar)
    left,right = st.columns(2)
    with left:
        st.markdown("**Confusion counts / Isolation Forest**")
        st.dataframe(pd.DataFrame([{
            "TN":i_f.get("true_negative",0),"FP":i_f.get("false_positive",0),
            "FN":i_f.get("false_negative",0),"TP":i_f.get("true_positive",0),
        }]), hide_index=True, use_container_width=True)
    with right:
        st.markdown("**Attack recall by scenario**")
        rec = section.get("attack_recall_by_scenario", {})
        if rec: st.bar_chart(pd.Series(rec, name="recall"))
    if partition == "test":
        df = pd.DataFrame(preds.get("rows", []))
    else:
        try:
            df = pd.DataFrame(load_api(endpoint(selected, "predictions", partition="validation", limit=1000)).get("rows", []))
        except RuntimeError as exc:
            st.error(str(exc));st.stop()
    if not df.empty:
        st.markdown("### Frozen-model anomaly scores")
        st.scatter_chart(df, x="anomaly_score", y="isolation_forest_pred", color="true_label")
        st.dataframe(df, hide_index=True, use_container_width=True)
    st.warning("Scores describe controlled simulated traffic. Do not infer real-world detector performance or recalibrate thresholds using test results.")
    with st.expander("Reported experiment limitations"):
        for limitation in metrics.get("limitations", []): st.write("• " + limitation)

else:
    if not selected_meta.get("has_robustness"):
        st.info("No robustness report available. Run scripts.audit_detector_robustness to generate it.")
        st.code("python -m scripts.audit_detector_robustness --input <run>/window_features.csv --ml-results <run>/ml_results --output <run>/ml_results/robustness_report.json", language="bash")
        st.stop()
    try:
        r = load_api(endpoint(selected, "robustness"))
    except RuntimeError as exc:
        st.error(str(exc)); st.stop()
    integrity = r.get("split_integrity", {})
    st.markdown("### Frozen-model verification")
    st.json(integrity)
    cases = r.get("what_if_cases", {})
    rows = []
    for case, data in cases.items():
        m = data.get("isolation_forest", {})
        rows.append({"case":case, "windows":data.get("n_windows"), "precision":m.get("precision"),
                     "recall":m.get("recall"),"false_positive_rate":m.get("false_positive_rate")})
    st.markdown("### What-if scenarios")
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.caption("These are feature-space counterfactuals, not independently observed attacks or new holdout samples.")
    with st.expander("Limitations"):
        for limitation in r.get("limitations", []):st.write("• " + limitation)
