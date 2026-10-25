# CyberSentinel Streamlit SOC v3 - NumPy test isolation fix

The offline test executes `dashboard/public_app.py` via `runpy.run_path` several times with a fake Streamlit module. The original mock allowed real pandas/NumPy imports during repeated in-process rendering, which may fail with `numpy: cannot load module more than once per process`.

## Change

In `EntryPointRegression.run_page`, mock the `pandas` module as well as `streamlit`. The fake `DataFrame` returns its input, sufficient because FakeStreamlit.dataframe does not interpret the object; the test exercises UI routing and markup, not Pandas computation. **No production app files are changed.**

## Apply

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
unzip -o ~/Downloads/CyberSentinel_SOC_V3_NumPy_Test_Fix.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m unittest discover -s tests -p test_streamlit_soc_v3.py -v
python -m unittest discover -s tests -v
python -c 'import numpy, pandas; print(numpy.__version__, pandas.__version__)'
streamlit run dashboard/public_app.py --server.address 127.0.0.1 --server.port 8501
```

Run the real Streamlit app in a fresh process. If importing NumPy or pandas alone still fails, it is an environment-level problem unrelated to this fake-UI test. Check virtual environment and import shadowing without deleting packages blindly.
