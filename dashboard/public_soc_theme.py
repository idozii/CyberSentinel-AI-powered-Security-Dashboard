"""First-party, presentation-only SOC-inspired theme for the public Streamlit showcase.

Do not import localhost monitoring stores here: Community Cloud serves research
summaries and a bounded passive HTTPS header checker, not live owner telemetry.
"""
from __future__ import annotations

PUBLIC_SOC_UI_VERSION = "public-soc-v2.1"

CSS = r"""
<style>
:root { color-scheme: dark; }
html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
  background: #07111d !important; color: #e7eff9 !important;
}
.stApp { background: radial-gradient(ellipse 760px 500px at 75% -200px, #163d4b 0%, transparent 76%), #07111d !important; }
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stToolbar"] { color: #a8b8cc; }
.block-container { max-width: 1470px !important; padding-top: 1.15rem !important; padding-bottom: 3.5rem !important; }
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0c1b2b 0%, #091522 95%) !important;
  border-right: 1px solid #1b3649 !important;
}
[data-testid="stSidebar"] * { color: #e2ebf6 !important; }
[data-testid="stSidebar"] [data-testid="stRadio"] > label {color: #94acbf !important; text-transform: uppercase; letter-spacing: 0.09em; font-size: 11px;}
[data-testid="stSidebar"] [role="radiogroup"] label {
  border-radius: 9px !important; padding: 7px 10px !important; margin: 3px 0;
  transition: background .12s ease;
}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {background: #142b3c !important;}
[data-testid="stSidebar"] [data-testid="stAlert"] {background:#102a35 !important; border: 1px solid #214959 !important; border-radius: 12px !important;}
[data-testid="stSidebar"] [data-testid="stLinkButton"] a {background:#113044 !important; border:1px solid #2e6674 !important;}
[data-testid="stMetric"] {
  background: linear-gradient(155deg, #13293c 0%, #0c1b2b 100%) !important;
  border:1px solid #274356 !important; border-radius:15px !important;
  padding:19px 21px !important; min-height:115px;
  box-shadow: 0 10px 26px rgba(0,0,0,.13);
}
[data-testid="stMetricLabel"] p { color:#a3b9cb !important; font-size:.86rem !important; }
[data-testid="stMetricValue"] { color:#f3faff !important; font-weight:750 !important; letter-spacing:-.03em;}
[data-testid="stMetricDelta"] {color:#4cd2c0 !important;}
[data-testid="stVerticalBlockBorderWrapper"] > div {border-color:#294457 !important;}
[data-testid="stForm"] { border:1px solid #2a485b !important; background: #0e2132 !important; border-radius:15px !important; }
[data-testid="stExpander"] {border:1px solid #2a485b !important; background: #0e2132 !important; border-radius:12px !important;}
[data-testid="stAlert"] {border-radius:12px !important;}
[data-testid="stDataFrame"] {border-radius:12px !important; overflow:hidden;}
[data-testid="stTextInput"] input,
[data-testid="stSelectbox"] input {background: #101f30 !important; color:#f0f7ff !important; border-color:#2c465b !important; border-radius:9px !important;}
.stButton > button[kind="primary"], [data-testid="stFormSubmitButton"] button {
  background: #17ac9f !important; border: 1px solid #35c6b7 !important;
  color: #061b21 !important; font-weight: 750 !important; border-radius:9px !important;
}
.stButton > button:hover, [data-testid="stFormSubmitButton"] button:hover {border-color:#5af3db !important;}
button, a {transition: border-color .12s ease, background .12s ease;}
h1, h2, h3 {letter-spacing: -.028em !important; color:#f2f9ff !important;}
h2 {margin-top: 1.15rem !important;}
p, li {line-height:1.55 !important;}
a { color: #52cfd4; }
.public-hero {
  display:flex; gap:22px; flex-direction:column; justify-content:space-between;
  border:1px solid #2b4d60; border-radius:18px; padding:28px 31px;
  background: radial-gradient(ellipse 700px 290px at 90% 10%, rgba(24,167,167,.17), transparent 80%),
              linear-gradient(116deg,#142d40 0%,#0b1b2b 66%,#091523 100%);
  box-shadow: 0 18px 35px rgba(0,0,0,.14); margin-bottom:19px;
}
.public-eyebrow { color:#57daca; letter-spacing:.17em; font-size:.68rem; font-weight:800; margin-bottom:9px; }
.public-hero h1 { color:#f5fbff; margin:0 0 12px; font-size:clamp(1.8rem, 3.2vw, 2.9rem); font-weight:770; line-height:1.12; }
.public-hero h1 em {font-style:normal; color:#69e2d2;}
.public-description {color:#b8cadd; font-size:1.04rem; margin:0; max-width:780px;}
.public-status-row {display:flex; gap:9px; flex-wrap:wrap; align-items:center;}
.public-tag {display:inline-flex; gap:7px; align-items:center; background:#102c39;
  border:1px solid #2b6871; border-radius:100px; padding:7px 12px;
  color:#a4e8e2; font-size:.71rem; font-weight:760; letter-spacing:.02em;}
.public-tag.secondary {background:#122239; border-color:#37516b; color:#afc6df;}
.public-tag svg {display:block;}
.public-status-dot {display:inline-block; width:7px; height:7px; background:#50ddbc; border-radius:100%; box-shadow:0 0 0 3px #205f5a;}
.public-disclosure {color:#849cb0; font-size:.76rem; margin-top:8px;}
@media(max-width: 680px) {
  .block-container {padding: .7rem 1rem 2.1rem !important;}
  .public-hero {padding: 22px 18px; border-radius:12px;}
  .public-hero h1 {font-size:1.8rem;}
  [data-testid="stMetric"] {min-height:92px; padding:13px 14px !important;}
}
</style>
"""

HERO = """
<section class="public-hero" aria-label="CyberSentinel public portfolio">
  <div>
    <div class="public-eyebrow">CYBERSENTINEL / PUBLIC RESEARCH WORKSPACE</div>
    <h1>Security intelligence,<br><em>clearly explained.</em></h1>
    <p class="public-description">Explore a bounded passive HTTPS posture checker and reproducible, aggregate results from a controlled local security telemetry experiment.</p>
  </div>
  <div class="public-status-row" aria-label="Available functionality">
    <span class="public-tag"><span class="public-status-dot"></span> PASSIVE HTTPS CHECKER</span>
    <span class="public-tag secondary">SYNTHETIC RESEARCH METRICS</span>
    <span class="public-tag secondary">OWNER MONITORING: LOCAL ONLY</span>
  </div>
  <div class="public-disclosure">PUBLIC SOC UI v2.1 / Portfolio showcase. Not a live SOC or production security service.</div>
</section>
"""


def apply_public_theme(streamlit_module) -> None:
    """CSS only, no dynamic HTML, script execution, remote data or secrets."""
    streamlit_module.markdown(CSS, unsafe_allow_html=True)


def render_public_hero(streamlit_module) -> None:
    streamlit_module.markdown(HERO, unsafe_allow_html=True)
