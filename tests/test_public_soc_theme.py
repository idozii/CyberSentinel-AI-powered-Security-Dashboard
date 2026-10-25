"""Public SOC theme regression: presentation does not expose localhost SOC services."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dashboard.public_soc_theme import CSS, HERO, PUBLIC_SOC_UI_VERSION
from scripts.install_public_soc import patch_source, install


class PublicThemeTest(unittest.TestCase):
    def test_labels_do_not_claim_live_monitoring(self):
        self.assertEqual(PUBLIC_SOC_UI_VERSION, 'public-soc-v2.1')
        self.assertIn('SYNTHETIC RESEARCH METRICS', HERO)
        self.assertIn('OWNER MONITORING: LOCAL ONLY', HERO)
        self.assertIn('Not a live SOC', HERO)
        self.assertNotIn('<script', CSS + HERO)
        self.assertNotIn('postgresql://', CSS + HERO)
        self.assertNotIn('Agent Key', CSS + HERO)

    def test_original_public_app_is_patched_without_changing_business_logic(self):
        old = '''from public_data import load_public_metrics
from site_checker import SiteCheckError, check_website
st.set_page_config(page_title="CyberSentinel | Research Showcase", page_icon="🛡️", layout="wide")
st.markdown("""\n<style>.hero{background: blue;}</style>\n""", unsafe_allow_html=True)
with st.sidebar:
    st.caption("AI-assisted security telemetry research")
    st.info("OWNER MONITORING: planned, not yet available.")
st.markdown("""\n<div class="hero"><h1>CyberSentinel / Research Explorer</h1></div>\n""", unsafe_allow_html=True)
KEEP_THIS_CHECKER_FUNCTION = 'unchanged'
'''
        new = patch_source(old)
        compile(new, '<public_app>', 'exec')
        self.assertIn('KEEP_THIS_CHECKER_FUNCTION', new)
        self.assertIn('render_public_hero(st)', new)
        self.assertIn('apply_public_theme(st)', new)
        self.assertEqual(new, patch_source(new))
        self.assertNotIn('Research Explorer</h1>', new)

    def test_install_never_overwrites_unrecognized_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'dashboard').mkdir()
            app = root / 'dashboard/public_app.py'
            app.write_text('print("different app")\n')
            (root / 'dashboard/public_soc_theme.py').write_text('CSS = ""\n')
            with self.assertRaises(ValueError):
                install(root)
            self.assertEqual(app.read_text(), 'print("different app")\n')


if __name__ == '__main__':
    unittest.main()
