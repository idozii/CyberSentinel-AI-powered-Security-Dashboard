"""CyberSentinel public portfolio showcase (static, aggregate-only).

Deploy this entrypoint on Streamlit Community Cloud: dashboard/public_app.py.
The original dashboard/app.py and dashboard_api/ remain localhost-only tools.
No external API calls, model deserialization, uploaded files or traffic capture.
"""
from __future__ import annotations

import pandas as pd
import streamlit as st
import time
from site_checker import SiteCheckError, check_website
from public_data import load_public_metrics

REPO = "https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard"
REPORT = REPO + "/blob/main/docs/EXPERIMENT_RESULTS.md"
ARCH = REPO + "/blob/main/docs/PROJECT_ARCHITECTURE.md"
REPRO = REPO + "/blob/main/docs/REPRODUCIBILITY.md"
SECURITY = REPO + "/blob/main/docs/SECURITY_AND_LIMITATIONS.md"

st.set_page_config(page_title="CyberSentinel | Research Showcase", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {max-width: 1400px; padding-top: 2.0rem; padding-bottom: 3rem;}
[data-testid="stSidebar"] {background: #0E1929;}
[data-testid="stSidebar"] * {color: #E7F1FC !important;}
div[data-testid="stMetric"] {border:1px solid #263A53; border-radius:13px; padding:14px 19px;
                                background:linear-gradient(150deg,#14263A,#101B2B);}
.hero {border:1px solid #314B64; border-radius:17px; padding:24px 28px;
       background:linear-gradient(110deg,#142C40,#101927); margin-bottom:22px;}
.hero h1 {font-size:2.05rem; font-weight:720; margin:0; color:#F1F9FF;}
.hero .subtitle {margin-top:10px; color:#B3D6DC; line-height:1.5;}
.pill {display:inline-block; margin-top:14px; color:#79E5D8; border:1px solid #337D7E;
       padding:5px 11px; border-radius:50px; font-size:0.78rem; font-weight:650;}
.muted {color:#AFC0D1; font-size:0.91rem;}
</style>
""", unsafe_allow_html=True)

try:
    data = load_public_metrics()
except (OSError, ValueError, KeyError, TypeError) as exc:
    st.error("Bundled public experiment summary is missing or inconsistent.")
    st.caption(f"Diagnostic: {exc}")
    st.stop()

source = data["source"]
split = data["splits"]
test = data["test"]
model = data["model"]

with st.sidebar:
    st.markdown("### 🛡️ CyberSentinel")
    st.caption("AI-assisted security telemetry research")
    st.divider()
    st.info("LIVE: passive HTTPS header check.\n\nRESEARCH: static lab evaluation.\n\nOWNER MONITORING: planned, not yet available.")
    page = st.radio("Explore", ["Website Checker", "Owner Monitoring (Roadmap)", "Overview", "Traffic & Features", "Model Evaluation", "Architecture & Limitations"])
    st.divider()
    st.link_button("Source on GitHub ↗", REPO, use_container_width=True)
    st.link_button("Read full experiment report ↗", REPORT, use_container_width=True)
    st.caption("No raw logs, private IP addresses, credentials or model files are hosted by this app.")

st.markdown("""
<div class="hero"><h1>CyberSentinel / Research Explorer</h1>
<div class="subtitle">Passive public HTTPS configuration checks and transparent, controlled research results.</div>
<span class="pill">LIVE HEADER CHECK · NO INTRUSIVE SCANNING · OWNER MONITORING PLANNED</span></div>
""", unsafe_allow_html=True)
if page in ("Website Checker", "Owner Monitoring (Roadmap)"):
    st.caption("CURRENT MODE: " + ("passive public HTTPS configuration check" if page == "Website Checker" else "owner monitoring product roadmap"))
else:
    st.caption(f"RECORDED EXPERIMENT · {source['date']} · seed {source['seed']} · {source['window_seconds']}-second windows · data provenance: user-reported local run")

if page == "Website Checker":
    st.subheader("Check public website configuration")
    st.write("Enter a public domain to examine its **HTTPS certificate connection** and a few HTTP security headers. "
             "CyberSentinel sends exactly one `HEAD /` request on HTTPS port 443; no redirects, crawling, "
             "login attempts, vulnerability probes, or malicious-content analysis.")
    st.warning("This is **not** a security certification or hacked/not-hacked verdict. "
               "Some sites redirect or reject HEAD requests; those results will remain unscored.")
    with st.form("check_public_site"):
        domain = st.text_input("Public hostname", placeholder="www.example.com", max_chars=240)
        submit = st.form_submit_button("Check HTTPS posture")
    if submit:
        # Per-session friction for the public demo, NOT a replacement for global
        # ingress quotas/WAF/identity-based limits for unattended production.
        history = [t for t in st.session_state.get("checker_attempts", []) if time.monotonic() - t < 600]
        if len(history) >= 3:
            st.error("Demo limit: 3 attempts per 10 minutes per browser session. Try again later.")
        else:
            history.append(time.monotonic())
            st.session_state["checker_attempts"] = history
            try:
                with st.spinner("Checking one HTTPS response..."):
                    result = check_website(domain)
                st.success(f"TLS certificate verified for {result['hostname']}")
                st.caption(f"Method: {result['method']} / · HTTP status: {result['http_status']} · Redirects: not followed")
                if result["status"] == "evaluated":
                    st.metric("Header configuration score", f"{result['score']} / {result['max_score']}")
                    st.caption(result["disclaimer"])
                    table = pd.DataFrame([{"Check": c["label"], "Result": "Observed" if c["passed"] else "Review", "Weight": c["points"]}
                                          for c in result["checks"]])
                    st.dataframe(table, hide_index=True, use_container_width=True)
                    st.info("Scores only describe a handful of response headers and do not prove exploitability or safety.")
                else:
                    st.info(result["message"])
            except SiteCheckError as exc:
                st.error(str(exc))
    st.caption("Privacy: no access log or result persistence is implemented in this demo. The checked website and its DNS resolver may observe your assessment request. "
               "For a broadly public production service, add central rate limits and network egress restrictions.")

elif page == "Owner Monitoring (Roadmap)":
    st.subheader("CyberSentinel for website owners")
    st.info("LIVE OWNER MONITORING IS NOT AVAILABLE YET. This page describes the next implementation phases.")
    st.markdown("**1. Verify ownership** - sign in and prove domain control with DNS TXT or a restricted HTTPS challenge.")
    st.markdown("**2. Install an agent** - consent-based log or OpenTelemetry integration; no bodies or credentials collected.")
    st.markdown("**3. Review live alerts** - per-tenant ingestion, bounded time windows, rules, anomaly scores and retention controls.")
    st.markdown("**4. Manage privacy** - revoke agent credentials, delete events and configure alert destinations.")
    st.warning("The current Isolation Forest prototype missed 17/24 simulated attack windows in its holdout. It must not be used to make automatic security decisions for customer websites.")

elif page == "Overview":
    a, b, c, d = st.columns(4)
    a.metric("Simulated requests", f"{source['simulated_requests']:,}")
    b.metric("Labels matched", f"{source['matched_requests']:,}")
    c.metric("Feature windows", f"{source['feature_windows']:,}")
    d.metric("Manifest gaps", source["manifest_gaps"])
    st.subheader("Experiment composition")
    left, right = st.columns([1.75, 1], gap="large")
    with left:
        counts = data["windows_by_scenario"]
        names = {"simulated_benign": "Benign", "simulated_brute_force": "Brute-force",
                 "simulated_path_scan": "Path scanning", "simulated_mixed_attack": "Mixed attack"}
        chart = pd.DataFrame({"Scenario": [names[x] for x in counts], "Windows": list(counts.values())})
        st.bar_chart(chart.set_index("Scenario"), y="Windows", color="#46B7AE")
        st.caption("40 independent simulated runs in each class. No raw request records are published.")
    with right:
        st.markdown("#### End-to-end coverage")
        st.write("**160** simulation sessions · **14** numeric model features")
        st.write(f"**{source['excluded_historical_events']}** historical unmatched events excluded rather than relabeled benign")
        st.write(f"**{split['train_benign_windows']}** benign training windows")
        st.write(f"**{split['validation_windows']} / {split['test_windows']}** validation / holdout windows")
        st.caption("The 160 windows are grouped by simulation run for evaluation, not live deployment.")
    st.subheader("Research takeaway")
    st.warning("At the selected threshold, Isolation Forest missed 17 of 24 simulated attack windows on the test set, including all 8 path-scanning windows. This is an experimental limitation-not a production security result.")

elif page == "Traffic & Features":
    st.subheader("Simulation coverage")
    st.write("The traffic generator sent only bounded HTTP requests to its **localhost** demo target. Scenarios describe the simulator's intended behavior; they do not prove real-world malicious intent.")
    labels = {"Benign": "simulated_benign", "Brute-force": "simulated_brute_force",
              "Path scanning": "simulated_path_scan", "Mixed attack": "simulated_mixed_attack"}
    scenario = st.selectbox("Scenario", list(labels))
    windows = data["windows_by_scenario"][labels[scenario]]
    c1, c2, c3 = st.columns(3)
    c1.metric("Scenario windows", windows)
    c2.metric("Total feature windows", source["feature_windows"])
    c3.metric("Time window", f"{source['window_seconds']}s")
    explanations = {
        "Benign": "Demo page and health requests; the original benign lab traffic contained few HTTP failures.",
        "Brute-force": "Repeated failed logins on the demo /login endpoint; unsuccessful requests produced HTTP 401.",
        "Path scanning": "Requests to common probe paths; the local demo returned HTTP 404.",
        "Mixed attack": "One replay containing both failed logins and path probes."
    }
    st.info(explanations[scenario])
    st.subheader("Features passed to the model")
    groups = [
        ("Request volume", ["request_count", "request_rate_per_second"]),
        ("Methods and authentication", ["get_ratio", "post_ratio", "login_attempt_count", "failed_login_count"]),
        ("Exploration and HTTP errors", ["unique_path_count", "http_401_ratio", "http_404_ratio", "http_4xx_ratio", "query_ratio"]),
        ("Latency and payload", ["mean_duration_ms", "mean_request_bytes", "mean_response_bytes"]),
    ]
    detail = pd.DataFrame([{"Group": category, "Feature": name} for category, names in groups for name in names])
    st.dataframe(detail, hide_index=True, use_container_width=True)
    st.caption("Source IP, raw URL paths, User-Agent, request ID and simulation label are not model inputs. Aggregations can still encode simulator-specific behavior.")

elif page == "Model Evaluation":
    st.subheader("Holdout evaluation")
    partition = st.segmented_control("View", ["Test", "Validation"], default="Test")
    details = test if partition == "Test" else data["validation"]
    metrics = details["isolation_forest"]
    a, b, c, d = st.columns(4)
    a.metric("Precision", f"{metrics['precision']:.1%}")
    b.metric("Recall", f"{metrics['recall']:.1%}")
    c.metric("F1-score", f"{metrics['f1']:.1%}")
    d.metric("Average precision", f"{metrics['ap']:.3f}")
    st.subheader("Isolation Forest confusion counts")
    tab = pd.DataFrame([{"True negatives": metrics["tn"], "False positives": metrics["fp"],
                         "False negatives": metrics["fn"], "True positives": metrics["tp"]}])
    st.dataframe(tab, hide_index=True, use_container_width=True)
    if partition == "Test":
        st.subheader("Against a fixed-rule baseline")
        rule = test["fixed_rule"]
        compare = pd.DataFrame({"Metric": ["Precision", "Recall", "F1"],
                                "Isolation Forest": [metrics[k] for k in ("precision", "recall", "f1")],
                                "Fixed rules": [rule[k] for k in ("precision", "recall", "f1")]})
        st.bar_chart(compare.set_index("Metric"))
        st.caption("The perfect fixed-rule score reflects obvious attack signatures in this synthetic lab, not real-world generalization.")
        st.subheader("Attack recall by scenario")
        scenario = test["attack_scenarios"]
        breakdown = pd.DataFrame([{"Scenario": name, "Detected": rec["detected"],
                                   "Total": rec["total"], "Recall": rec["detected"] / rec["total"]}
                                  for name, rec in scenario.items()])
        st.bar_chart(breakdown.set_index("Scenario"), y="Recall", color="#49BCAF")
        st.dataframe(breakdown, hide_index=True, use_container_width=True)
        st.error("Path scanning: 0 of 8 windows detected. Isolation Forest should not be deployed as a standalone security detector on the basis of this lab.")
    else:
        st.info("Validation used only eight benign windows. A nominal 5% target FPR cannot be estimated precisely from such a small set; one error implies 12.5% observed FPR.")
    st.caption("Results are a static snapshot from the recorded 24 October 2026 run. No model inference is executed on this website.")

else:
    st.subheader("System architecture")
    steps = [
        ("01", "Local NGINX reverse proxy", "Structured JSON request telemetry + issued request IDs"),
        ("02", "Collector & ETL", "Normalize logs into JSONL/CSV events"),
        ("03", "Trusted label join", "Match replay manifest by request ID; unknown events remain unlabeled"),
        ("04", "Feature windows", "14 numeric aggregates per simulation run and 60-second interval"),
        ("05", "Isolation Forest + fixed rules", "Fit on benign training, calibrate on benign validation"),
        ("06", "Evaluation & audit", "Run-disjoint holdout, frozen-model what-if checks and CI"),
        ("07", "Local experiment explorer", "Read-only FastAPI + Streamlit for local artifacts"),
    ]
    for index, title, detail in steps:
        st.markdown(f"**{index} · {title}**")
        st.caption(detail)
    st.divider()
    st.subheader("What is and is not hosted publicly")
    st.success("Hosted: aggregate class counts, confusion matrices, selected experimental metrics, technical methodology.")
    st.warning("Not hosted: local access logs, raw traffic events, individual request IDs/IPs, the model .joblib, credentials, the Docker lab, or the localhost API.")
    st.subheader("Research and deployment limitations")
    for limitation in [
        "This is static evidence from a controlled simulation-not live monitoring or incident alerting.",
        "Repeated attack templates and simplified benign behavior restrict external validity.",
        "Per-run windows cannot be reused as a live inference grouping policy without redesign.",
        "The original test set contained 75% attack windows, unlike many operational environments.",
        "Public deployment does not make the underlying prototype a production IDS.",
    ]:
        st.write("• " + limitation)
    st.link_button("Read experiment methodology ↗", REPORT)
    st.link_button("Architecture documentation ↗", ARCH)
    st.link_button("Reproduce local experiment ↗", REPRO)
    st.link_button("Security and limitations ↗", SECURITY)

st.divider()
st.caption("CyberSentinel · Educational/research prototype · Aggregate report from one local experiment · Source and documentation on GitHub")
