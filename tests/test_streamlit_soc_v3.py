"""Offline public SOC v3 tests - no Streamlit installed, network or secrets needed."""
from __future__ import annotations

import importlib.util
import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / 'dashboard'

sys.path.insert(0, str(DASH))
from public_soc_layout import STYLE, VERSION, bars, brand, evidence, heading, hero, kpi, progress_panel
from public_data import load_public_metrics


class LayoutUnit(unittest.TestCase):
    def test_contains_actual_soc_components(self):
        self.assertIn('cs-hero', hero())
        self.assertIn('Security visibility', hero())
        self.assertIn('cs-brand', brand())
        self.assertIn('PUBLIC RESEARCH', heading('Overview'))
        self.assertIn('cs-kpi-value', kpi('test', '14', 'synthetic'))
        self.assertIn('cs-bar-fill', bars('Chart','synthetic',['A','B'],[10,20]))
        self.assertIn('cs-progress-fill', progress_panel('Metric','research',[('TP',5,''),('FN',2,'red')]))
        self.assertIn('cs-evidence-row', evidence([('Rule','Test','low','')]))
        self.assertIn('background:#080f1b', STYLE)
        self.assertEqual(VERSION, 'public-soc-v3.0')

    def test_html_content_escaped_and_charts_validate_input(self):
        for rendered in [heading('<img src=x>'), kpi('<script>','<script>','test'),
                         evidence([('<img>','<script>','tag','')]),
                         bars('<svg>','example',['<script>'],[1])]:
            self.assertNotIn('<script>', rendered)
            self.assertNotIn('<img>', rendered)
            self.assertNotIn('<svg>', rendered)
        with self.assertRaises(ValueError):
            bars('chart','test',['bad'],[-1])
        with self.assertRaises(ValueError):
            progress_panel('chart','test',[('bad',-1,'red')])
        with self.assertRaises(ValueError):
            evidence([('title','test','tag','not-allowed')])

    def test_public_metrics_are_original_validated_bundle(self):
        metrics=load_public_metrics()
        self.assertEqual(metrics['source']['simulated_requests'],2678)
        self.assertEqual(metrics['test']['isolation_forest']['fn'],17)
        self.assertEqual(metrics['display_mode'],'static_research_summary')

    def test_cloud_root_theme_configuration(self):
        import tomllib
        obj=tomllib.loads((ROOT/'.streamlit/config.toml').read_text())
        self.assertEqual(obj['theme']['base'],'dark')
        self.assertEqual(obj['theme']['backgroundColor'],'#080F1B')


class FakeStreamlit(types.ModuleType):
    def __init__(self, page):
        super().__init__('streamlit')
        self.page=page
        self.output=[]
        self.session_state={}
        self.sidebar=self
        self.reruns=0

    def __enter__(self):
        return self

    def __exit__(self,*args):
        return False

    def markdown(self, value, **kw):
        self.output.append(('markdown',str(value)))

    def radio(self, label, choices, **kw):
        assert self.page in choices
        return self.page

    def columns(self, count, **kw):
        return [self]* (count if isinstance(count,int) else len(count))

    def segmented_control(self, *args, **kw):
        return kw.get('default','Test')

    def selectbox(self, title, options, **kw):
        return options[0]

    def form(self,*args,**kw):
        return self

    def text_input(self,*args,**kw):
        return 'www.example.com'

    def form_submit_button(self,*args,**kw):
        return False

    def button(self,*args,**kw):
        return False

    def stop(self,*args,**kw):
        raise RuntimeError('Application stopped unexpectedly')

    def rerun(self,*args,**kw):
        self.reruns+=1

    def __getattr__(self,name):
        def func(*args,**kw):
            self.output.append((name,str(args[0]) if args else ''))
        return func


class EntryPointRegression(unittest.TestCase):
    def run_page(self,page):
        fake=FakeStreamlit(page)
        # Mock both UI and DataFrame construction for this in-process render test.
        # Importing real pandas may reinitialize NumPy extension modules when a
        # larger test suite has manipulated sys.modules earlier in the process.
        # Integration with real pandas/Streamlit is checked by the real app smoke.
        fake_pandas = types.ModuleType('pandas')
        fake_pandas.DataFrame = lambda values: values
        with patch.dict(sys.modules, {'streamlit': fake, 'pandas': fake_pandas}):
            runpy.run_path(str(DASH / 'public_app.py'), run_name='__main__')
        return fake

    def test_overview_is_first_page_and_materially_redesigned(self):
        source=(DASH/'public_app.py').read_text()
        self.assertIn('NAV = ["Overview", "Website checker"',source)
        app=self.run_page('Overview')
        markup='\n'.join(x[1] for x in app.output if x[0]=='markdown')
        self.assertIn('Security visibility,',markup)
        self.assertIn('cs-kpi-value',markup)
        self.assertIn('cs-bar-chart',markup)
        self.assertIn('cs-progress-fill',markup)
        self.assertIn('cs-evidence-row',markup)
        self.assertIn('NOT LIVE MONITORING',markup)
        self.assertIn('2,678',markup)
        self.assertIn('17 / 24',markup)

    def test_every_page_renders_without_network(self):
        for page in ['Overview','Website checker','Traffic & features','Model evaluation','Architecture','Owner roadmap']:
            with self.subTest(page=page):
                app=self.run_page(page)
                markup='\n'.join(x[1] for x in app.output if x[0]=='markdown')
                self.assertIn('cs-footer',markup)

    def test_checker_and_validated_metric_source_retained(self):
        source=(DASH/'public_app.py').read_text()
        self.assertIn('from site_checker import SiteCheckError, check_website',source)
        self.assertIn('from public_data import load_public_metrics',source)
        self.assertIn('with st.form("check_public_site")',source)
        self.assertIn('result = check_website(domain)',source)
        for forbidden in ['hosted_api.monitoring','CYBERSENTINEL_PG_RUNTIME_DSN','CYBERSENTINEL_AGENT_KEY','Auth0 Client Secret']:
            self.assertNotIn(forbidden,source)


if __name__=='__main__':
    unittest.main()
