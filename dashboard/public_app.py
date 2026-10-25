"""CyberSentinel - public SOC-style research showcase on Streamlit Cloud.

This is NOT the private FastAPI monitoring system. The dashboard uses only a
bundled, validated aggregate experiment summary and a bounded passive HTTPS
header checker. No monitoring store, credentials, raw logs or live alerts.
"""
from __future__ import annotations

import time
from html import escape

import pandas as pd
import streamlit as st

from public_data import load_public_metrics
from public_soc_layout import STYLE, VERSION, bars, brand, evidence, footer, heading, hero, kpi, notice, progress_panel
from site_checker import SiteCheckError, check_website

REPO = "https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard"
REPORT = REPO + "/blob/main/docs/EXPERIMENT_RESULTS.md"
ARCH = REPO + "/blob/main/docs/PROJECT_ARCHITECTURE.md"
REPRO = REPO + "/blob/main/docs/REPRODUCIBILITY.md"
SECURITY = REPO + "/blob/main/docs/SECURITY_AND_LIMITATIONS.md"
NAV = ["Overview", "Website checker", "Traffic & features", "Model evaluation", "Architecture", "Owner roadmap"]
CLASS_LABELS = {
    "simulated_benign": "Benign",
    "simulated_brute_force": "Brute-force",
    "simulated_path_scan": "Path scanning",
    "simulated_mixed_attack": "Mixed",
}

st.set_page_config(page_title="CyberSentinel | Public SOC Research", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
st.markdown(STYLE, unsafe_allow_html=True)

try:
    data = load_public_metrics()
except (OSError, ValueError, KeyError, TypeError) as exc:
    st.error("Bundled aggregate experiment data is missing or inconsistent.")
    st.caption(f"Diagnostic: {exc}")
    st.stop()

source, split, test = data["source"], data["splits"], data["test"]

with st.sidebar:
    st.markdown(brand(), unsafe_allow_html=True)
    st.markdown('<div class="cs-side-heading">WORKSPACE</div>', unsafe_allow_html=True)
    page = st.radio("Navigate", NAV, key="public_soc_page", label_visibility="collapsed")
    st.divider()
    st.link_button("View source on GitHub", REPO, use_container_width=True)
    st.link_button("Read experiment report", REPORT, use_container_width=True)
    st.markdown('<div class="cs-side-box"><span class="cs-dot"></span><strong>Public portfolio</strong><br>'
                'Static research data + passive HTTPS check<br>Owner monitoring runs on localhost only.</div>',
                unsafe_allow_html=True)

st.markdown(heading({"Overview":"Security overview", "Website checker":"Website checker",
                     "Traffic & features":"Traffic explorer", "Model evaluation":"Model evaluation",
                     "Architecture":"System architecture", "Owner roadmap":"Owner monitoring roadmap"}[page]),
            unsafe_allow_html=True)

if page == "Overview":
    st.markdown(hero(), unsafe_allow_html=True)
    cols = st.columns(4, gap="small")
    metrics = [
        ("Simulated requests", f"{source['simulated_requests']:,}", "Controlled localhost NGINX lab", "↗", ""),
        ("Labeled windows", f"{source['feature_windows']:,}", "Run-disjoint experiment windows", "▤", "blue"),
        ("Missed attacks", f"{test['isolation_forest']['fn']} / {split['test_attack']}", "Isolation Forest holdout", "!", "warn"),
        ("Monitoring mode", "Research", "No live tenant data", "⌁", ""),
    ]
    for col, values in zip(cols, metrics):
        with col:
            st.markdown(kpi(*values), unsafe_allow_html=True)

    st.markdown('<div class="cs-section-title"><div class="cs-overline">RESEARCH TELEMETRY</div>'
                '<h3>Experiment insights</h3></div>', unsafe_allow_html=True)
    left, right = st.columns([1.5, 1], gap="medium")
    with left:
        counts = data["windows_by_scenario"]
        st.markdown(bars("Traffic scenario composition", "160 synthetic simulation windows, not live HTTP events",
                         [CLASS_LABELS[k] for k in counts], list(counts.values())), unsafe_allow_html=True)
    with right:
        m = test["isolation_forest"]
        st.markdown(progress_panel("Detection outcome", "Isolation Forest - held-out experiment",
                                  [("Correct detections (TP)", m["tp"], ""),
                                   ("Missed attacks (FN)", m["fn"], "red"),
                                   ("Correct benign (TN)", m["tn"], "blue"),
                                   ("False alarms (FP)", m["fp"], "yellow")]), unsafe_allow_html=True)

    st.markdown('<div class="cs-section-title"><div class="cs-overline">INVESTIGATION</div>'
                '<h3>Scenario-level research evidence</h3></div>', unsafe_allow_html=True)
    detection = test["attack_scenarios"]
    st.markdown(evidence([
        (name, f"Detected {row['detected']} of {row['total']} attack windows - holdout fixture",
         f"{row['detected']}/{row['total']} detected", "danger" if row["detected"] == 0 else "warn")
        for name, row in detection.items()
    ]), unsafe_allow_html=True)
    st.markdown(notice("These are experimental detection counts, not active alerts. The local FastAPI SOC at 127.0.0.1:8019 is a separate, private demonstration service."),
                unsafe_allow_html=True)

    def _navigate(target: str) -> None:
        # Streamlit callback runs before widgets are instantiated on the rerun.
        st.session_state["public_soc_page"] = target

    a, b = st.columns(2, gap="medium")
    with a:
        st.markdown("### Public website checker")
        st.caption("One passive HTTPS HEAD request on port 443. No scanning or exploit tests.")
        st.button("Open HTTPS checker", type="primary", use_container_width=True,
                  on_click=_navigate, args=("Website checker",))
    with b:
        st.markdown("### Detailed model evaluation")
        st.caption("Precision, recall, confusion matrix, and known failure modes.")
        st.button("Open model evaluation", use_container_width=True,
                  on_click=_navigate, args=("Model evaluation",))

elif page == "Website checker":
    st.markdown(notice("PASSIVE HTTPS HEADER CHECK ONLY. This is not a security certification, vulnerability scan, or hacked/not-hacked verdict."),
                unsafe_allow_html=True)
    st.markdown("### Check one public HTTPS hostname")
    st.caption("One HEAD / request using hostname-validated TLS on port 443. No redirects, crawling, authentication attempts, or probes.")
    with st.form("check_public_site"):
        domain = st.text_input("Public hostname", placeholder="www.example.com", max_chars=240)
        submit = st.form_submit_button("Check HTTPS posture", type="primary", use_container_width=True)
    if submit:
        now = time.monotonic()
        attempts = [t for t in st.session_state.get("checker_attempts", []) if now - t < 600]
        if len(attempts) >= 3:
            st.error("Demo limit: 3 attempts per 10 minutes per browser session. Try later.")
        else:
            attempts.append(now)
            st.session_state["checker_attempts"] = attempts
            try:
                with st.spinner("Checking one HTTPS response..."):
                    result = check_website(domain)
                st.success(f"TLS certificate verified for {result['hostname']}")
                st.caption(f"Method: {result['method']} / · HTTP status: {result['http_status']} · No redirects followed")
                if result["status"] == "evaluated":
                    left, right = st.columns([1, 2])
                    with left:
                        st.metric("Header configuration score", f"{result['score']} / {result['max_score']}")
                    with right:
                        st.caption(result["disclaimer"])
                    st.dataframe(pd.DataFrame([
                        {"Check": x["label"], "Result": "Observed" if x["passed"] else "Review", "Weight": x["points"]}
                        for x in result["checks"]]), hide_index=True, use_container_width=True)
                    st.info("Header configuration completeness does not establish that the website is secure.")
                else:
                    st.info(result["message"])
            except SiteCheckError as exc:
                st.error(str(exc))
    st.caption("Privacy: no local access logs or checker results are persisted by this UI. The target may observe your request. "
               "Per-session quota is not a global ingress limit; public deployment also needs external controls.")

elif page == "Traffic & features":
    st.markdown(notice("All traffic was generated against an authorized local Docker/NGINX lab; there is no stream of live client requests here."),
                unsafe_allow_html=True)
    counts = data["windows_by_scenario"]
    left, right = st.columns([1.5, 1], gap="medium")
    with left:
        st.markdown(bars("Simulation breakdown", "Run-disjoint class composition",
                         [CLASS_LABELS[k] for k in counts], list(counts.values())), unsafe_allow_html=True)
    with right:
        st.markdown(progress_panel("Data coverage", "Source manifest quality",
                                  [("Matched requests", source["matched_requests"], ""),
                                   ("Manifest gaps", source["manifest_gaps"], "yellow")]), unsafe_allow_html=True)
    scenario = st.selectbox("Inspect a scenario", list(CLASS_LABELS.values()))
    descriptions = {
        "Benign":"Health and demo page requests in a controlled benign replay.",
        "Brute-force":"Repeated failed logins returning HTTP 401 from the lab endpoint.",
        "Path scanning":"Requests to common probe paths returning HTTP 404 in the lab.",
        "Mixed":"Combination of failed logins and path probes in one replay.",
    }
    a,b,c = st.columns(3)
    a.metric("Scenario windows", counts[next(k for k,v in CLASS_LABELS.items() if v == scenario)])
    b.metric("Window length", f"{source['window_seconds']}s")
    c.metric("Features", source["features"])
    st.info(descriptions[scenario])
    groups = [
        ("Request volume", ["request_count", "request_rate_per_second"]),
        ("Methods & authentication", ["get_ratio", "post_ratio", "login_attempt_count", "failed_login_count"]),
        ("Exploration & errors", ["unique_path_count", "http_401_ratio", "http_404_ratio", "http_4xx_ratio", "query_ratio"]),
        ("Latency & payload", ["mean_duration_ms", "mean_request_bytes", "mean_response_bytes"]),
    ]
    st.subheader("Feature engineering")
    st.dataframe(pd.DataFrame([{"Group": group, "Feature": feature} for group, features in groups for feature in features]),
                 hide_index=True, use_container_width=True)
    st.caption("Source IP, raw URL, User-Agent, request IDs and simulation labels are not fed into the model.")

elif page == "Model evaluation":
    st.markdown(notice("This assessment comes from a static synthetic holdout. It is not a real-world intrusion detection performance claim."),
                unsafe_allow_html=True)
    partition = st.segmented_control("Partition", ["Test", "Validation"], default="Test")
    metrics = test["isolation_forest"] if partition == "Test" else data["validation"]["isolation_forest"]
    for col, info in zip(st.columns(4, gap="small"), [
        ("Precision", f"{metrics['precision']:.1%}", "Synthetic holdout", "◈", ""),
        ("Recall", f"{metrics['recall']:.1%}", "Detection sensitivity", "↗", "blue"),
        ("F1 score", f"{metrics['f1']:.1%}", "Precision / recall", "▤", ""),
        ("Avg precision", f"{metrics['ap']:.3f}", "Ranking metric", "⌁", "warn"),
    ]):
        with col:
            st.markdown(kpi(*info), unsafe_allow_html=True)
    a, b = st.columns([1.5, 1], gap="medium")
    with a:
        st.markdown(progress_panel("Confusion matrix", "Counts on selected partition",
                                  [("True positive", metrics["tp"], ""),
                                   ("False negative", metrics["fn"], "red"),
                                   ("True negative", metrics["tn"], "blue"),
                                   ("False positive", metrics["fp"], "yellow")]), unsafe_allow_html=True)
    with b:
        st.markdown(evidence([
            ("True positives", "Actual attacks detected", str(metrics["tp"]), ""),
            ("False negatives", "Missed attack windows", str(metrics["fn"]), "danger"),
            ("True negatives", "Correct benign windows", str(metrics["tn"]), ""),
            ("False positives", "Benign windows flagged", str(metrics["fp"]), "warn"),
        ]), unsafe_allow_html=True)
    if partition == "Test":
        rules = test["fixed_rule"]
        st.subheader("Fixed-rule baseline comparison")
        st.dataframe(pd.DataFrame({"Metric": ["Precision", "Recall", "F1"],
                     "Isolation Forest": [metrics[k] for k in ("precision", "recall", "f1")],
                     "Fixed rules": [rules[k] for k in ("precision", "recall", "f1")]}),
                     hide_index=True, use_container_width=True)
        st.caption("The perfect fixed-rule score reflects obvious signatures in this synthetic lab, not deployment accuracy.")
        st.subheader("Attack recall by scenario")
        st.markdown(evidence([(name, f"Detected {row['detected']} of {row['total']} windows",
                              f"{row['detected'] / row['total']:.0%} recall",
                              "danger" if row["detected"] == 0 else "warn")
                             for name,row in test["attack_scenarios"].items()]),unsafe_allow_html=True)
        st.error("Path scanning: 0 of 8 windows detected. Do not deploy Isolation Forest as a standalone IDS on this evidence.")
    else:
        st.info("Validation included only eight benign windows; one error corresponds to 12.5% observed false-positive rate.")
    st.caption(f"Recorded {source['date']} · seed {source['seed']} · no live model inference on this website")

elif page == "Architecture":
    st.markdown(notice("Public Streamlit and the private localhost SOC are separate runtimes with different data-access boundaries."),
                unsafe_allow_html=True)
    layers = [
        ("01 - NGINX lab", "Controlled localhost traffic + structured request telemetry", "LOCAL ONLY", ""),
        ("02 - ETL & labels", "Local collector, strict request-ID matching, run-disjoint features", "LOCAL ONLY", ""),
        ("03 - Detection experiment", "Isolation Forest compared with fixed rules", "RESEARCH", "warn"),
        ("04 - Public showcase", "Aggregate summaries + passive HTTPS header checker", "PUBLIC", ""),
        ("05 - Owner monitoring", "Private Auth0/PostgreSQL staging and localhost demo", "NOT PUBLIC", "danger"),
    ]
    st.markdown(evidence(layers), unsafe_allow_html=True)
    st.subheader("Privacy boundary")
    st.success("Public: aggregate scenario counts, confusion counts, documented methodology and header configuration checks.")
    st.warning("Not public: access logs, private telemetry, raw IPs, model files, tenant credentials, owner portal, live alerts.")
    for label, url in (("Experiment report", REPORT),("Project architecture", ARCH),
                       ("Reproducibility", REPRO),("Security & limitations", SECURITY)):
        st.link_button(label, url)

else:
    st.markdown(notice("Owner monitoring is not available through this public Streamlit website. The SOC dashboard from Step 31-32 is a localhost-only demonstration."),
                unsafe_allow_html=True)
    st.markdown(evidence([
        ("Ownership verification", "Sign in and prove DNS control", "STAGING", "warn"),
        ("Consent-based telemetry", "Use a bounded agent without cookies, bodies or passwords", "LOCAL", "warn"),
        ("Tenant alert triage", "Review rule evidence and deduplicated alerts", "LOCAL", "warn"),
        ("Security hardening", "Credential isolation, backup/restore and operator review", "IN PROGRESS", "danger"),
        ("Controlled beta", "Domain, HTTPS, real consent and independent review", "NO-GO", "danger"),
    ]), unsafe_allow_html=True)
    st.warning("Isolation Forest missed 17/24 simulated attack windows in the recorded holdout. No production IDS claim is supported.")

st.markdown(footer(), unsafe_allow_html=True)
