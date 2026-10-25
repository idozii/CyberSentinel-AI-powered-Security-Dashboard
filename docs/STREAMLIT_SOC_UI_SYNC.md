# CyberSentinel - Streamlit public UI sync

## Why public Streamlit was still old

The SOC v2 UI added at Steps 31-32 belongs to the localhost FastAPI server (`hosted_api/local_demo.py`, `hosted_api/soc_ui.py`) on `127.0.0.1:8019`. Streamlit Community Cloud runs `dashboard/public_app.py` separately. FastAPI changes do not deploy into Streamlit automatically.

## Apply on the current main branch

1. Confirm you have no local edits and synchronize main.
2. Create a feature branch `feat/streamlit-public-soc-ui`.
3. Unzip `CyberSentinel_Streamlit_Public_SOC_UI.zip` at repository root.
4. Run `python -m scripts.install_public_soc` - this modifies **only** `dashboard/public_app.py`, preserving its existing Website Checker, aggregate lab metrics, safeguards, and route content.
5. Run `python -m scripts.install_public_soc --check`, `python -m unittest discover -s tests -p test_public_soc_theme.py -v`, `python -m scripts.release_audit`, and `git diff --check`.
6. For a local preview: `python -m pip install -r requirements-dashboard.txt && streamlit run dashboard/public_app.py --server.address 127.0.0.1 --server.port 8501`.
7. Commit `dashboard/public_app.py`, `dashboard/public_soc_theme.py`, `scripts/install_public_soc.py`, `tests/test_public_soc_theme.py`, `docs/STREAMLIT_SOC_UI_SYNC.md`, push your branch, create PR, and merge after CI.
8. Streamlit Community Cloud: check repository `idozii/CyberSentinel-AI-powered-Security-Dashboard`, **branch `main`**, and **main file `dashboard/public_app.py`**. If the deployment points to `dashboard/app.py` or another repository/branch, switch it to the correct public entrypoint.
9. On Cloud, reboot the app only if a fresh commit has been merged but it does not refresh. Refresh the browser cache after reboot.

Expected visible marker: **PUBLIC SOC UI 2.1** and a dark cyan/blue research dashboard. Public SOC **styling** is inspired by the localhost SOC dashboard, but this Streamlit app remains a separate **static public portfolio showcase** - not the private live SOC or Auth0/Neon owner console.

## Security boundary

Never expose the FastAPI local demo on public Internet, never copy `csd_`, `csa_`, or `csp_` keys to Streamlit secrets, and do not put private telemetry or Neon credentials in this public app. Its Website Checker is a bounded passive HTTPS configuration check; it is not a security scan, incident investigation, or guarantee of website safety.
