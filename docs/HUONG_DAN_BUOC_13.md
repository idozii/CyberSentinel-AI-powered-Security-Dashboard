# CyberSentinel - Buoc 13: Continuous Agent & Reliability

## Muc tieu

Buoc 13 mo rong package Step 11-12 bang lenh `cybersentinel-agent-watch` de doc NGINX JSONL lien tuc tren **localhost**, gui events da toi gian hoa va luu outbox SQLite neu API khong san sang. `cybersentinel-agent` (one-shot) van con nguyen.

- Doc theo byte offset va inode (khong doc lai tat ca file sau moi poll).
- Giu dong JSON chua ket thuc boi newline, khong dua vao outbox.
- Khi NGINX doi ten access.log va tao file moi, co gang doc het old inode roi moi chuyen file; co gang tim `access.log.*` tren restart.
- Ghi event da giam thieu va cursor trong **cung mot SQLite transaction**.
- Xoa event trong outbox **chi sau khi server tra ve receipt hop le**. Khi retry sau crash co the gui trung, nhung API Step 11-12 co event ID deduplication.
- Retry exponential backoff cho loi mang/HTTP 429/HTTP 5xx. Dung va giu hang doi khi HTTP 401/422.
- Gioi han toi da 1,000 events trong outbox. Khong doc them khi hang doi day.
- Khong luu raw IP, query, cookies, passwords hoac raw log trong state DB.

**Phan biet:** Day la *foreground local log follower* voi outbox, khong phai distributed 24/7 monitoring service. Khong mo port 8002 ra Internet. Khong deploy owner API hoac owner portal len public Streamlit Cloud.

## 13.1 Kiem tra branch va cai files

Tu repo root, `git status` phai sach. Neu co thay doi chua commit, hay luu lai truoc khi chuyen branch.

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/continuous-agent-step13

unzip -l ~/Downloads/CyberSentinel_Buoc_13_Continuous_Agent.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_13_Continuous_Agent.zip -d .
```

ZIP chi bo sung `cybersentinel_agent/continuous.py`, `watch_cli.py`, tests va docs, cap nhat `pyproject.toml`, `owner_portal/app.py`, `scripts/release_audit.py`, `README.md`. Khong thay API Step 12, ownership, key hay detection rules.

## 13.2 Install + tests

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt
python -m pip install -e .

python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
cybersentinel-agent-watch --help
```

**Ky vong repo day du: 170 tests PASS** (148 Step 12 + 22 Step 13). Ban sao ma nguon local trong qua trinh phat trien dat 165 tests PASS, vi thieu 5 tests collector/ETL tu repo GitHub day du.

## 13.3 Chuan bi API va domain

Terminal A:

```bash
uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
```

Terminal B (tuy chon, de xem alerts):

```bash
streamlit run owner_portal/app.py --server.address 127.0.0.1 --server.port 8503
```

Dang nhap Owner Portal, chon domain da verify DNS, lay domain ID va API key agent cu da tao o Step 11. Khong chia se key trong chat, terminal logs, screenshots hay GitHub. Nhap vao bien moi truong:

```bash
read -rsp 'Agent key: ' CYBERSENTINEL_AGENT_KEY; echo
export CYBERSENTINEL_AGENT_KEY
```

## 13.4 Demo watcher voi NGINX logs gia lap

Tao file co 6 login failures moi, chi la local JSONL, khong gui bat cu request nao den website ben ngoai:

```bash
python -m scripts.generate_step12_demo_logs --scenario failed-login
```

**Lan dau, de doc 6 dong san co**, dung `--from-start` va state file rieng cho demo:

```bash
cybersentinel-agent-watch \
  --input simulations/runtime/owner/step12_demo_nginx.jsonl \
  --state simulations/runtime/owner/step13_demo_state.sqlite3 \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID \
  --from-start --iterations 3 --poll-seconds 1
```

Khi data du moi (trong khoang 5 phut) va key dung, ky vong lan dau: `read_lines: 6`, `accepted: 6` va `queued: 0`. Neu event IDs da duoc gui truoc do, server se tra `duplicates: 6` thay vi accepted. Neu co 5+ failed logins trong cung cua so 60 giay, Owner Portal se co alert High severity (neu chua co alert cho cua so do).

**Quan trong:** `--from-start` chi ap dung khi state file chua co cursor. Neu chay lai voi **cung state**, watcher tiep tuc tu cursor cu, khong doc tu dau. Neu chua co state va bo qua `--from-start`, watcher bat dau tu cuoi file hien tai va chi xu ly lines moi duoc ghi sau khi khoi dong.

## 13.5 Theo doi NGINX access.log lien tuc

Tao agent theo doi log trong Docker lab va cap nhat Owner Portal:

```bash
cybersentinel-agent-watch \
  --input simulations/runtime/logs/access.log \
  --state simulations/runtime/owner/nginx_watcher.sqlite3 \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID \
  --poll-seconds 1
```

De terminal nay chay foreground. Agent bat dau tu **cuoi file** neu state la moi. Tao benign/attack-like events bang **simulations local** da co trong repo, khong tro den website ben ngoai. Bam Ctrl+C de dung; outbox/cursor duoc luu. Chay lai cung lenh de tiep tuc.

### Doc output

| Truong | Y nghia |
|---|---|
| `read_lines` | So dong JSONL da consume trong poll |
| `queued` | So events da sanitized dang cho send |
| `delivery.state` | `empty`, `sent`, `backoff`, hoac `retry` |
| `accepted_total` | So events duoc server chap nhan trong process hien tai |
| `duplicates_total` | So events server nhan la trung trong process hien tai |
| `rotation_recovery_warning` | Co kha nang bo sot old rotated file luc watcher khong chay |

Console khong in credentials, raw IP hoac raw URLs. API key duoc doc tu environment; outbox SQLite luu events da sanitized, khong luu key dang plain text.

## 13.6 Khi API mat ket noi hoac backlog qua cu

Khi API mat ket noi tam thoi, watcher retry voi backoff (2, 4, 8 ... 60 giay), giu events va cursor trong SQLite. Trong luc API down, outbox toi da 1,000 events; neu day, watcher dung doc them. Khong co auto-drop.

API Step 11-12 **chi chap nhan events co timestamp cach thoi diem ingest toi da 5 phut**. Neu backlog qua 5 phut, watcher fail closed de nguoi van hanh kiem tra. Khong the bao dam gui duoc events qua cu voi API nay. Khong co co che rewrite timestamp.

Khi chap nhan mat du lieu cu la can thiet trong lab, co the xoa **chi cac queued events qua 5 phut** bang lenh minh thi ro rang:

```bash
cybersentinel-agent-watch \
  --input simulations/runtime/logs/access.log \
  --state simulations/runtime/owner/nginx_watcher.sqlite3 \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID \
  --purge-expired --confirm-loss --iterations 1
```

Sau khi purge, neu log goc con nhieu dong cu **chua doc**, watcher van co the stop o dong cu do. Giai phap dung trong lab: tao file log moi, su dung state file moi, hoac log rotation duoc quan ly. **Khong tu dong bo qua hoac sua timestamp log that.**

Sau khi thay doi API key, domain ID hoac input log, phai dung **state file moi**, vi cu state rang buoc voi key + domain + log path va co the con events cua key cu.

## 13.7 Cac gioi han chua giai quyet

- Inode recovery chi co gang tim `access.log.*` trong cung folder. Neu log rotated da bi xoa/compress/doi ten ngoai mau trong luc agent tat, co the mat lines chua doc. Output se canh bao.
- Copytruncate duoc phat hien khi kich thuoc file giam duoi offset. Truong hop truncate va ghi file moi rat nhanh truoc khi poll co the khong phat hien duoc.
- Khong dap ung 24/7 reliability, SLA, externally hosted endpoints, TLS, remote agent, monitoring/metrics endpoint, dead-letter queue hoac backup SQLite.
- Server max 300 events / domain / rolling minute. Du lieu tro nen cu se bi tu choi sau 5 phut.
- Event ID HMAC giup dedup; source pseudonym thay doi theo UTC day va key.
- Invalid/oversized JSONL dung watcher, khong skip de tranh silent loss; nguoi van hanh can dieu tra file va restart.
- `--from-start` voi old log se bi tu choi neu events da qua 5 phut.
- Khong de SQLite state tren shared volume hoac commit vao repo.

Xem `docs/AGENT_RELIABILITY.md` cho decision log va mo hinh tinh dung.

## 13.8 Commit va PR

```bash
git add README.md pyproject.toml scripts/release_audit.py owner_portal/app.py \
  cybersentinel_agent/continuous.py cybersentinel_agent/watch_cli.py \
  tests/test_step13_continuous.py \
  docs/HUONG_DAN_BUOC_13.md docs/AGENT_RELIABILITY.md

git diff --cached --check
git diff --cached --stat
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check

git commit -m "feat: add durable continuous localhost telemetry follower"
git push -u origin feat/continuous-agent-step13
```

Tao PR vao `main`. Chi merge khi Python 3.12, Python 3.13 va Docker smoke PASS. Khong `git add -A` hoac commit runtime DB, logs, agent key.

## Huong phat trien Step 14

Deploy hosted owner platform voi HTTPS, database ben vung, managed identity, event quotas/retention, authz, audit logging, monitoring, and controlled API ingress. Khong public hoa Step 10-13 localhost-only API truoc khi hoan tat.
