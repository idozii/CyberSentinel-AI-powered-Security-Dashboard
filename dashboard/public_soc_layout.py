"""Pure, static visual elements for the public Streamlit SOC showcase.

This module deliberately never imports hosted_api, tenant stores, or secrets.
All experiment values have been validated by public_data before rendering.
"""
from __future__ import annotations

from html import escape

VERSION = "public-soc-v3.0"

STYLE = r"""
<style>
:root {color-scheme:dark;}
html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
  background:#080f1b !important; color:#e7edf7 !important;
}
[data-testid="stHeader"] {background:rgba(8,15,27,.88) !important; border-bottom:1px solid #202d42;}
[data-testid="stToolbar"] {color:#b9cada !important;}
[data-testid="stSidebar"] {background:#0d1524 !important; border-right:1px solid #263247 !important;}
[data-testid="stSidebar"] * {color:#dce8f5 !important;}
[data-testid="stSidebar"] [role="radiogroup"] label {
  border:1px solid transparent; border-radius:10px; padding:9px 10px !important; margin:2px 0;
  background:transparent; transition:.2s background,.2s border-color;
}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {background:#18283b; border-color:#294456;}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background:#133746 !important; border-color:#2a616b !important;
}
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {color:#8c9db6 !important;}
.block-container {max-width:1490px !important; padding-top:1.65rem !important; padding-bottom:3rem !important;}
h1,h2,h3 {color:#f4f8ff !important;letter-spacing:-.035em !important;}
p {line-height:1.55;}
a {color:#65ddc8;}
[data-testid="stVerticalBlockBorderWrapper"] {border-radius:14px !important;}
[data-testid="stVerticalBlockBorderWrapper"] > div {border-color:#29384d !important;}
[data-testid="stDataFrame"], [data-testid="stForm"], [data-testid="stExpander"] {
  background:#101b2c !important; border-radius:14px !important; border-color:#283c55 !important;
}
[data-testid="stTextInput"] input {background:#101d30 !important; color:#f0f7ff !important;}
[data-testid="stMetric"] {background:#101c2d !important;border:1px solid #273952 !important;padding:18px;border-radius:14px !important;}
.stButton button[kind="primary"], [data-testid="stFormSubmitButton"] button {
  background:#4edac4 !important;color:#072026 !important;border:1px solid #4edac4 !important;
  border-radius:9px !important;font-weight:750 !important;
}
.stButton button[kind="secondary"] {background:#17283d !important;border:1px solid #304862 !important;color:#e5f0f9 !important;border-radius:9px !important;}
.stButton button:hover {border-color:#76f2df !important;}
.cs-brand {display:flex;align-items:center;gap:12px;margin:7px 0 28px;}
.cs-logo {height:42px;width:42px;display:grid;place-items:center;background:linear-gradient(145deg,#207e85,#0e4253);
  border:1px solid #3bafb1;border-radius:12px;color:#85f6df;font-size:28px;font-weight:800;box-shadow:0 0 22px #1d938521;}
.cs-brand-name {font-size:15px;font-weight:800;letter-spacing:.025em;}
.cs-brand-name span{color:#53dfcd;}
.cs-brand-detail {font-size:9px;letter-spacing:.2em;color:#7e94ad !important;}
.cs-side-heading {font-size:10px;letter-spacing:.2em;color:#758ca6 !important;margin:16px 0 7px;font-weight:750;}
.cs-side-box {border-top:1px solid #243347;margin-top:14px;padding-top:16px;color:#8d9fb7;font-size:11px;}
.cs-dot {display:inline-block;height:8px;width:8px;border-radius:50%;background:#51dfc3;margin-right:7px;box-shadow:0 0 0 3px #2c78622e;}
.cs-topbar {display:flex;align-items:center;justify-content:space-between;padding:0 0 22px;gap:10px;
  color:#94a7be;font-size:12px;}
.cs-topbar strong {color:#e5eef9;} .cs-topbar-badge {border:1px solid #275068;background:#112a39;color:#a6e3e1;
  border-radius:6px;padding:5px 9px;font-size:10px;font-weight:800;letter-spacing:.07em;}
.cs-overline {color:#4de0c8;font-size:10px;font-weight:800;letter-spacing:.18em;line-height:1.6;}
.cs-heading {font-size:30px;font-weight:820;letter-spacing:-.04em;color:#f4f9ff;margin:5px 0 18px;line-height:1.15;}
.cs-hero {position:relative;overflow:hidden;display:flex;align-items:center;justify-content:space-between;
  min-height:213px;border:1px solid #2b596b;border-radius:15px;padding:29px 32px;margin-bottom:18px;
  background:radial-gradient(circle at 84% 19%,#19536677,transparent 42%),linear-gradient(115deg,#152f3e,#0d1e31 78%);}
.cs-hero-copy {position:relative;z-index:1;max-width:700px;}
.cs-hero-label {font-size:10px;color:#86e7d5;letter-spacing:.16em;font-weight:780;}
.cs-hero-title {font-size:clamp(25px,2.6vw,38px);font-weight:820;letter-spacing:-.045em;color:#f3f8fc;line-height:1.12;margin:16px 0 11px;}
.cs-hero-title em {color:#52dfc6;font-style:normal;}
.cs-hero-sub {max-width:520px;color:#b1c1d5;font-size:13px;line-height:1.7;}
.cs-hero-mark {height:154px;width:154px;flex:0 0 154px;border:1px solid #2f838a;border-radius:50%;margin-right:30px;
  display:grid;place-items:center;color:#58ead0;font-size:66px;font-weight:700;transform:rotate(-9deg);
  box-shadow:0 0 0 16px #1b777522,0 0 0 33px #11667418,inset 0 0 32px #246f7455;}
.cs-badges {display:flex;gap:9px;margin-top:19px;flex-wrap:wrap;}
.cs-badge {border:1px solid #396276;background:#143449;color:#a8ebdd;border-radius:7px;padding:6px 10px;font-size:10px;font-weight:800;letter-spacing:.05em;}
.cs-badge.muted {background:#18283a;color:#b2c2d8;border-color:#334b63;}
.cs-kpi {background:#101b2c;border:1px solid #283a53;border-radius:14px;min-height:140px;padding:19px 21px;}
.cs-kpi-top {display:flex;justify-content:space-between;align-items:center;gap:8px;color:#b4c4d7;font-size:12px;}
.cs-kpi-icon {height:28px;width:28px;border-radius:7px;background:#1a574f;color:#6ef3d0;display:grid;place-items:center;font-size:15px;}
.cs-kpi-icon.warn {background:#573d23;color:#f5c57b;}.cs-kpi-icon.blue {background:#253958;color:#a0c8ff;}
.cs-kpi-value {font-size:30px;font-weight:820;color:#f7faff;letter-spacing:-.055em;margin:15px 0 2px;line-height:1.1;}
.cs-kpi-note {color:#8098b1;font-size:11px;}
.cs-section-title {margin:22px 0 10px;} .cs-panel {border:1px solid #293a52;background:#101b2c;border-radius:15px;
 padding:20px 22px;min-height:278px;}
.cs-panel-top {color:#61e2cf;letter-spacing:.15em;font-size:10px;font-weight:790;}
.cs-panel h3 {font-size:19px;margin:7px 0 3px;}.cs-panel-desc{color:#95a8be;font-size:11px;}
.cs-bar-chart {display:flex;align-items:flex-end;gap:12px;height:178px;padding:25px 4px 5px;}
.cs-bar-wrap {display:flex; flex-direction:column;align-items:center;flex:1;min-width:0;gap:7px;}
.cs-bar-track {height:118px;max-width:92px;width:100%;background:#182c42;border-radius:6px 6px 1px 1px;display:flex;align-items:flex-end;overflow:hidden;}
.cs-bar-fill {width:100%;border-radius:6px 6px 0 0;background:linear-gradient(0deg,#219f96,#53e5ce);}
.cs-bar-num {font-size:11px;color:#8deadd;}.cs-bar-label{font-size:10px;color:#a3b5c8;text-align:center;overflow-wrap:anywhere;}
.cs-progress {margin:18px 0 21px;}.cs-progress-head {display:flex;justify-content:space-between;color:#b8c7d8;font-size:12px;margin-bottom:8px;}
.cs-progress-track {height:7px;background:#283a50;border-radius:8px;overflow:hidden;}
.cs-progress-fill {height:100%;background:#4be0c3;border-radius:8px;}
.cs-progress-fill.yellow {background:#ffbf70;}.cs-progress-fill.red{background:#ed6f85;}.cs-progress-fill.blue{background:#91b6f8;}
.cs-evidence {background:#101b2c;border:1px solid #293a52;border-radius:13px;overflow:hidden;margin:10px 0 18px;}
.cs-evidence-row {padding:13px 18px;border-bottom:1px solid #26374e;display:flex;justify-content:space-between;gap:14px;align-items:center;}
.cs-evidence-row:last-child{border:0}.cs-evidence-row strong{font-size:13px;color:#e5f1fb;}
.cs-evidence-row small{display:block;font-size:11px;color:#8da2b9;margin-top:3px;}
.cs-chip{font-size:10px;font-weight:780;border-radius:6px;padding:5px 8px;color:#a8f0d9;background:#194c44;white-space:nowrap;}
.cs-chip.warn{background:#513a25;color:#ffd49c;}.cs-chip.danger{background:#582f3b;color:#ffc1cf;}
.cs-info{padding:15px 18px;border:1px solid #2e556a;background:#112b3a;border-radius:12px;color:#bed2e5;font-size:12px;line-height:1.7;}
.cs-footer{border-top:1px solid #253449;margin-top:32px;padding-top:20px;color:#8395ae;font-size:11px;}
@media(max-width:950px){.cs-hero-mark{display:none}.cs-hero{min-height:190px}}
@media(max-width:650px){.block-container{padding:1rem 1rem 2rem !important}.cs-topbar{flex-wrap:wrap}.cs-heading{font-size:25px}
 .cs-hero{padding:20px}.cs-kpi{min-height:114px;padding:15px}.cs-kpi-value{font-size:24px}
 .cs-bar-chart{gap:6px}.cs-bar-label{font-size:9px}.cs-evidence-row{align-items:flex-start}}
</style>
"""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def brand() -> str:
    return '<div class="cs-brand"><span class="cs-logo">⌁</span><div><div class="cs-brand-name">CYBER<span>SENTINEL</span></div><div class="cs-brand-detail">SECURITY OPERATIONS</div></div></div>'


def heading(title: str, section: str = 'PUBLIC RESEARCH WORKSPACE') -> str:
    return ('<div class="cs-topbar"><div>Workspace &nbsp; / &nbsp; <strong>' + _e(title)
            + '</strong></div><span class="cs-topbar-badge">PUBLIC RESEARCH</span></div>'
            '<div class="cs-overline">CYBERSENTINEL / ' + _e(section) + '</div>'
            '<div class="cs-heading">' + _e(title) + '</div>')


def hero() -> str:
    return ('''<section class="cs-hero"><div class="cs-hero-copy">
      <div class="cs-hero-label"><span class="cs-dot"></span> RECORDED RESEARCH · PUBLIC SHOWCASE</div>
      <div class="cs-hero-title">Security visibility, <em>without the noise.</em></div>
      <div class="cs-hero-sub">Explore controlled NGINX telemetry experiments, transparent detection results, and a strictly bounded passive HTTPS header checker.</div>
      <div class="cs-badges"><span class="cs-badge">SYNTHETIC EVIDENCE</span>
      <span class="cs-badge muted">PASSIVE HTTPS CHECK</span><span class="cs-badge muted">NOT LIVE MONITORING</span></div>
      </div><div class="cs-hero-mark" aria-hidden="true">⌁</div></section>''')


def kpi(label: str, value: object, note: str, icon: str = '↗', tone: str = '') -> str:
    return ('<div class="cs-kpi"><div class="cs-kpi-top"><span>'+_e(label)+'</span><span class="cs-kpi-icon '+_e(tone)+'">'
            +_e(icon)+'</span></div><div class="cs-kpi-value">'+_e(value)+'</div><div class="cs-kpi-note">'+_e(note)+'</div></div>')


def bars(title: str, subtitle: str, labels: list[str], values: list[int]) -> str:
    if not labels or len(labels) != len(values) or any(type(v) is not int or v < 0 for v in values):
        raise ValueError('Invalid chart data')
    maximum = max(max(values), 1)
    parts = []
    for label, count in zip(labels, values):
        pct = round(100 * count / maximum, 2)
        parts.append('<div class="cs-bar-wrap"><div class="cs-bar-num">'+_e(count)+'</div>'
                     '<div class="cs-bar-track"><div class="cs-bar-fill" style="height:'+str(pct)+'%"></div></div>'
                     '<div class="cs-bar-label">'+_e(label)+'</div></div>')
    return ('<div class="cs-panel"><div class="cs-panel-top">RESEARCH TELEMETRY</div><h3>'+_e(title)+'</h3>'
            '<div class="cs-panel-desc">'+_e(subtitle)+'</div><div class="cs-bar-chart">'+''.join(parts)+'</div></div>')


def progress_panel(title: str, subtitle: str, rows: list[tuple[str, int, str]]) -> str:
    if any(type(n) is not int or n < 0 or tone not in ('','yellow','red','blue') for _,n,tone in rows):
        raise ValueError('Invalid progress data')
    total = sum(n for _, n, _ in rows)
    parts = []
    for label, n, tone in rows:
        pct = 0 if not total else round(n / total * 100, 2)
        parts.append('<div class="cs-progress"><div class="cs-progress-head"><span>'+_e(label)+'</span><strong>'
                     +_e(n)+'</strong></div><div class="cs-progress-track"><div class="cs-progress-fill '+tone
                     +'" style="width:'+str(pct)+'%"></div></div></div>')
    return ('<div class="cs-panel"><div class="cs-panel-top">EVALUATION</div><h3>'+_e(title)+'</h3>'
            '<div class="cs-panel-desc">'+_e(subtitle)+'</div>'+''.join(parts)+'</div>')


def evidence(rows: list[tuple[str, str, str, str]]) -> str:
    allowed_tones = {'', 'warn', 'danger'}
    items = []
    for title, description, tag, tone in rows:
        if tone not in allowed_tones:
            raise ValueError('Invalid evidence tone')
        items.append('<div class="cs-evidence-row"><div><strong>'+_e(title)+'</strong><small>'+_e(description)
                     +'</small></div><span class="cs-chip '+tone+'">'+_e(tag)+'</span></div>')
    return '<div class="cs-evidence">'+''.join(items)+'</div>'


def notice(message: str) -> str:
    return '<div class="cs-info">'+_e(message)+'</div>'


def footer() -> str:
    return ('<div class="cs-footer">CyberSentinel · Public Research Showcase · SOC UI v3.0 '
            ' · Static synthetic results · No private telemetry or active agent keys hosted</div>')
