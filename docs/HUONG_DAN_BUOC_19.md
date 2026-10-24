# CyberSentinel - Huong dan Buoc 19: Local Demo Mode

## Muc tieu

Bieu dien duoc luong: NGINX JSONL gia lap -> CyberSentinel Agent -> private
localhost ingest -> thong ke telemetry -> rule-based alerts -> dashboard.
**Khong can mua domain, dang nhap Auth0, ket noi Neon hay tao DNS TXT.**
Day la demo tach biet. Owner Portal `8007` va Postgres ingest `8008` giu
nguyen co che xac minh domain va RLS, khong co bypass.

## 0. Dieu kien

- PR Step 18 da merge vao `main`; `git status` sach.
- Linux/macOS + Python venv co `fastapi`, `uvicorn`, `httpx`, `argon2-cffi`,
  `pydantic`, va cac requirements da cai tu Step 18.
- Chay duoi user binh thuong, **khong sudo**, khong reverse proxy.
- **Khong dung** token `csp_`/`csa_`, database DSN, Auth0 secrets, hay NGINX
  log that cho demo. Token demo bat dau `csd_`.

## 1. Ap dung patch ZIP

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/isolated-local-demo-step19
unzip -o ~/Downloads/CyberSentinel_Buoc_19_Local_Demo.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m pip install -r requirements-owner.txt -r requirements-hosted.txt -r requirements-dashboard.txt
python -m pip install -e .
python -m unittest discover -s tests -p test_step19_demo.py -v
python -m scripts.step19_preflight
```

Neu branch da ton tai, khong tao lai `git switch -c`: chuyen vao branch
cu neu chua co commit can giu, hoac dung ten branch moi.

## 2. Khoi dong demo tren localhost

**Terminal A:**

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
source /home/idozii/envs/ds/bin/activate
export CYBERSENTINEL_LOCAL_DEMO=1
uvicorn hosted_api.local_demo:factory --factory --host 127.0.0.1 --port 8019 --workers 1
```

Mo `http://127.0.0.1:8019/`. Nhan **Generate new local demo key**.
Trang se hien Agent Key `csd_...` **mot lan** va `Demo Domain ID` dang 32
hex characters. Ghi lai Demo Domain ID (khong bi mat), sao chep token vao
password manager tam thoi. Chuyen trang hoac tai lai thi token khong hien
lai. Nhan tao key lan nua se reset tat ca demo data va thu hoi key cu.

**Port 8019 chi co tac dung demo.** Khong mo ra internet, khong dung
`--host 0.0.0.0`, Docker public ports, SSH tunnel hay Caddy forwarding.

## 3. Tao NGINX test log va gui tu Agent

**Terminal B:**

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
source /home/idozii/envs/ds/bin/activate
printf 'Step 19 demo key: '
IFS= read -rs CYBERSENTINEL_AGENT_KEY
printf '\n'
export CYBERSENTINEL_AGENT_KEY

python -m scripts.step19_generate_logs \
  --scenario login \
  --output /tmp/cybersentinel_step19_login.jsonl
```

Neu file output da ton tai, script tu choi ghi de. Doi ten file moi
(vi du them `_2`) hoac xoa file demo da tao.

Thay `PASTE_DEMO_DOMAIN_HEX` bang ID trong dashboard (KHONG phai ten
mien, localhost hay ID cua domain Neon):

```bash
python -m cybersentinel_agent.cli \
  --input /tmp/cybersentinel_step19_login.jsonl \
  --domain-id PASTE_DEMO_DOMAIN_HEX \
  --server http://127.0.0.1:8019
```

Ket qua ky vong (cac gia tri phu thuoc input):

```json
{
  "mode": "local-demo",
  "submitted": 5,
  "accepted": 5,
  "duplicates": 0,
  "alerts_updated": 1
}
```

Tai lai `http://127.0.0.1:8019/` de thay `5` events va alert
**Repeated login failures**. Nhan **Acknowledge** de danh dau da xem.

## 4. Kiem thu duplicate va 404 burst

Chay lai **dung lenh agent** o muc 3 voi cung file va key:

```json
{"accepted": 0, "duplicates": 5, "alerts_updated": 0}
```

Tao file moi de kiem thu 404:

```bash
python -m scripts.step19_generate_logs \
  --scenario 404 --output /tmp/cybersentinel_step19_404.jsonl
python -m cybersentinel_agent.cli \
  --input /tmp/cybersentinel_step19_404.jsonl \
  --domain-id PASTE_DEMO_DOMAIN_HEX \
  --server http://127.0.0.1:8019
```

Ky vong alert **HTTP 404 response burst**. Ban cung co the su dung
`--scenario 5xx` (nguong 5) va `--scenario traffic` (40 events). Voi traffic,
agent nhan toi da 25 events/mot batch, nen can tach input 40 dong lam 2
file (25 + 15) va gui hai lan. Moi file tao ra chi la log gia lap.

## 5. Kiem thu, commit va PR

```bash
python -m unittest discover -s tests -v
python -m scripts.step19_preflight
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
git diff --check
git status
git add README.md .github/workflows/ci.yml cybersentinel_agent/client.py \
  hosted_api/local_demo.py scripts/step19_generate_logs.py \
  scripts/step19_preflight.py tests/test_step19_demo.py \
  docs/HUONG_DAN_BUOC_19.md docs/STEP19_DEMO_SECURITY.md
git diff --cached --stat
git diff --cached --check
git commit -m "feat: add isolated localhost telemetry and alerts demo"
git push -u origin feat/isolated-local-demo-step19
```

Tao PR `feat/isolated-local-demo-step19 -> main`. Cho tat ca CI PASS,
kiem tra file log va token khong bi commit, sau do merge.

## 6. Gioi han va rollback

- Khong phai he thong phat hien xam nhap production; rules chi la nganh
  nguong, khong phai bang chung ve hanh vi tan cong.
- Khong co PostgreSQL RLS trong demo vi demo chi co 1 fake tenant va
  luu trong RAM. RLS cua staging van duoc test rieng trong CI.
- Khong persist. Stop `Ctrl+C` la mat events, alerts, token. Start lai
  thi co Domain ID moi. Day la chu y cua thiet ke, khong phai loi.
- Khong can migration hay Neon credentials; khong sua SQLite cu.
- `git revert` commit Step 19 hoac `git switch main` de quay ve Step 18.
