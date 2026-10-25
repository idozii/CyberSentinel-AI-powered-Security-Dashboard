# CyberSentinel - Actual SOC UI port for Streamlit Community Cloud

## What changed

This is a **full replacement of `dashboard/public_app.py`**, not merely a CSS patch.
The first page is now **Security overview** with four SOC-style KPI tiles, a
telemetry scenario bar chart, an evaluation breakdown, and scenario-level
research evidence. All public pages share a dark sidebar, topbar, and the new
SOC v3 visual design inspired by the private localhost dashboard.

The live monitoring features at `127.0.0.1:8019` are **not** available via
Streamlit Community Cloud. The public UI uses only validated bundled synthetic
aggregate data and retains the original passive HEAD-only HTTPS checker.
Do not enter Agent Keys, Auth0 credentials, or Neon DSNs into Streamlit secrets.

## Apply

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/streamlit-soc-v3-real-port
unzip -o ~/Downloads/CyberSentinel_Streamlit_SOC_V3_Full_Port.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m pip install -r dashboard/requirements.txt
python -m unittest discover -s tests -p test_streamlit_soc_v3.py -v
python -m unittest discover -s tests -p test_public_showcase.py -v
python -m unittest discover -s tests -p test_step9_site_checker.py -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
streamlit run dashboard/public_app.py --server.address 127.0.0.1 --server.port 8501
```

Verify the **Security overview** loads on first visit with the heading
`Security visibility, without the noise.` and the `PUBLIC RESEARCH` badge. The
main page is now visually and structurally different from the old Research
Explorer. Check the Website checker and Model evaluation page too.

## Push

```bash
git add dashboard/public_app.py dashboard/public_soc_layout.py \
  .streamlit/config.toml tests/test_streamlit_soc_v3.py \
  docs/STREAMLIT_SOC_V3_GUIDE.md
git diff --cached --check
git commit -m "feat: port actual SOC overview and navigation to public Streamlit"
git push -u origin feat/streamlit-soc-v3-real-port
```

Create PR, wait for CI PASS, merge to `main`. Then verify at Streamlit Community
Cloud that the deploy config is repository
`idozii/CyberSentinel-AI-powered-Security-Dashboard`, branch `main`, and
**Main file path `dashboard/public_app.py`**. This full port cannot display
from `hosted_api/local_demo.py`, which is a FastAPI server.

After the merge, if Streamlit Cloud still serves old code, open app settings,
check branch/path, and reboot. Check the runtime logs if the app fails to build.

Note: `.streamlit/config.toml` is at repository root, so it also changes the
visual theme of `dashboard/app.py` if launched separately via Streamlit, without
changing its API behavior.
