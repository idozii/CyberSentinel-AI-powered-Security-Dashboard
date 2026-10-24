# CyberSentinel - Huong dan Buoc 12: Local Detection & Alerts

## Muc tieu

Buoc 12 bo sung phat hien dua tren 4 quy tac minh bach, luu alert theo domain da xac minh DNS, owner xem va acknowledge alert, va giao dien tu tai lai moi 10 giay khi dang mo Owner Portal. Day la prototype tren localhost, khong phai dich vu giam sat 24/7 tren Internet. ML Isolation Forest cua Buoc 5 **khong** duoc dung de ra canh bao tu dong.

## 12.1 Tao branch

Chay trong thu muc goc CyberSentinel. Neu `git status` co thay doi chua commit, can luu chung truoc.

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/local-rule-alerts-step12
```

Tai ZIP `CyberSentinel_Buoc_12_Rule_Alerts.zip` va giai nen trong root repo:

```bash
unzip -l ~/Downloads/CyberSentinel_Buoc_12_Rule_Alerts.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_12_Rule_Alerts.zip -d .
```

## 12.2 Cai package va test

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt
python -m pip install -e .
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
python -m scripts.release_audit
```

Ket qua ky vong tren **repository day du**: 148 tests PASS (133 cu + 15 tests moi). Ban sao local dung de tich hop da pass 143/143 tests, khong co 5 tests collector/ETL co trong repo day du. Khong push/merge neu test fail.

## 12.3 Chay localhost API va Owner Portal

Terminal 1:

```bash
source .venv/bin/activate
uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
```

Terminal 2:

```bash
source .venv/bin/activate
streamlit run owner_portal/app.py --server.address 127.0.0.1 --server.port 8503
```

Truy cap `http://127.0.0.1:8503`. Dang nhap owner da tao o Buoc 10. Chon **domain da verify DNS** va tao agent key neu chua co. Dung lai key cua Buoc 11 neu da co, khong can tao key moi. API docs: `http://127.0.0.1:8002/docs`.

## 12.4 Tao 6 events login fail gia lap

Chi sinh NGINX JSONL trong thu muc ignored `simulations/runtime/owner/`; khong gui HTTP den bat ky website ben ngoai nao.

```bash
python -m scripts.generate_step12_demo_logs --scenario failed-login
```

Neu agent key chua nam trong environment, su dung terminal rieng va nhap key bi an:

```bash
read -rsp 'Agent key: ' CYBERSENTINEL_AGENT_KEY; echo
export CYBERSENTINEL_AGENT_KEY
```

Khong chia se agent key trong chat, screenshots hay GitHub. Lay `domain_id` tu Owner Portal (domain phai verify DNS):

```bash
cybersentinel-agent \
  --input simulations/runtime/owner/step12_demo_nginx.jsonl \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID
```

Ket qua ky vong: `submitted: 6`, `accepted: 6`, `duplicates: 0`, `alerts_updated: 1`. Day la **du doan**, phai xem output tren may ban de xac nhan. Mo Owner Portal, phan **Local detection alerts**. Trong vong khoang 10 giay khi trang dang mo, neu browser/Streamlit hoat dong, thay alert `Repeated login failures` voi severity `high`, count `6/5`, status `open`.

Bam **Acknowledge** se chuyen status thanh `acknowledged`. Neu chay lai lenh agent voi cung log trong vong 5 phut, server se ghi `duplicates: 6` va khong tao alert moi. Neu log qua 5 phut, tao log moi truoc khi gui lai.

Ban co the tao 2 demo khac:

```bash
python -m scripts.generate_step12_demo_logs --scenario missing-pages
cybersentinel-agent --input simulations/runtime/owner/step12_demo_nginx.jsonl \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID

python -m scripts.generate_step12_demo_logs --scenario server-errors
cybersentinel-agent --input simulations/runtime/owner/step12_demo_nginx.jsonl \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID
```

Neu gui nhieu demo trong cung 60 giay, tung rule co the tao alert rieng; chung la synthetic examples va khong phai thong tin attack that.

## 12.5 Xem API cua domain dang dang nhap

Neu co owner session bearer trong Swagger, su dung endpoint `GET /owner/domains/{domain_id}/alerts`, sau do `POST /owner/domains/{domain_id}/alerts/{alert_id}/acknowledge`. Chuc nang xac nhan chi co tac dung doi trang thai alert, khong chan request nao.

API `GET /owner/health` van tra `live_monitoring: false` vi day la local, one-shot agent, khong chay daemon hay dich vu hosted.

## 12.6 Commit va PR

```bash
git status
git add README.md owner_api/main.py owner_api/telemetry.py owner_api/detection.py \
  owner_portal/app.py cybersentinel_agent/client.py \
  scripts/generate_step12_demo_logs.py scripts/release_audit.py \
  tests/test_step12_alerts.py docs/HUONG_DAN_BUOC_12.md docs/OWNER_DETECTION_DESIGN.md
git diff --cached --stat
git diff --cached --check
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
python -m scripts.release_audit
git commit -m "feat: add local owner-scoped rule detection and alerts"
git push -u origin feat/local-rule-alerts-step12
```

Tao PR vao `main`, doi GitHub Actions jobs Python 3.12, 3.13 va Docker smoke PASS roi moi merge. KHONG `git add -A` neu co DB, logs, secrets, venv. `README.md` va cac tai lieu moi su dung dau `-` ASCII, khong co em dash/en dash.

## Gioi han

- Quy tac chi do threshold tren 60s windows; khong xac nhan attack. 404 burst co the chi la broken links.
- Nguon HMAC chi mang tinh pseudonym, thay doi theo ngay/key, khong phai client identity da xac thuc.
- Portal tu lam moi 10s chi khi trang dang mo. NGINX agent van can chay lenh gui events thu cong.
- Khong deploy owner API/Portal len public Streamlit Cloud hay expose port 8002 ra Internet.
- Khong co SMS/email, notification queue, WebSocket, background worker, hosted database hoac reliable ingestion daemon.
- Thu nghiem khong thay the test voi legitimate real-world traffic va khong chung minh FPR/reliability.

Xem `docs/OWNER_DETECTION_DESIGN.md` de biet schema, rules va mo hinh bao mat chi tiet.
