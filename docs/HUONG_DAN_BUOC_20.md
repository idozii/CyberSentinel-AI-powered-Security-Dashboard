# CyberSentinel - Huong dan Buoc 20: Detection Evaluation va Benchmarking

## 0. Dieu kien

- Buoc 19 da merge vao `main` (PR #21); neu local `main` chua duoc dong bo, chay `git pull --ff-only origin main`.
- Buoc nay CHI dung du lieu tong hop va `DemoStore` tren RAM, khong dung Auth0, Neon, role owner, real IP hay production log.
- Khong nen goi ket qua duoi day la do chinh xac nhan dien cyberattack tren Internet.

## 1. Tao nhanh va ap dung ban va

Tu repository root, dam bao khong co thay doi chua commit can giu:

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/synthetic-detection-evaluation-step20
unzip -o ~/Downloads/CyberSentinel_Buoc_20_Detection_Evaluation.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m pip install -r requirements-owner.txt -r requirements-hosted.txt
python -m pip install -e .
```

ZIP la patch - chi gom file duoc them/sua trong Buoc 20.

## 2. Chay benchmark khong can server

```bash
python -m scripts.step20_evaluate
```

Ket qua mong doi voi rules hien tai:

```text
14 synthetic scenarios, 4 rules, 56 scenario-rule pairs
TP=4, FP=2, FN=2, TN=48
Precision=0.6667, Recall=0.6667, F1=0.6667
```

Don vi danh gia la **mot cap (scenario, rule)**, khong phai mot HTTP event, mot tan cong hay mot nguoi dung. Ground truth do nguoi viet fixture gan nhan. Cac case benign_missing_links va benign_health_polling duoc co y gan benign de do false alarms; cac case low_rate_login_attempts va slow_path_probe duoc gan suspicious de do missed detections.

Lua chon xuat hai file khong chua credential:

```bash
python -m scripts.step20_evaluate --output-dir /tmp/cybersentinel-step20-report
```

Se tao `step20_evaluation.json` va `step20_evaluation.md`, voi quyen file `0600`. Thu muc can CHUA ton tai, nam ngoai repository va duoc tao o che do `0700`. Neu da co thu muc, dung ten moi - cong cu co y tu choi ghi de. Khong commit output thoi diem chay vao GitHub.

## 3. Xem tren localhost dashboard

Trong terminal:

```bash
export CYBERSENTINEL_LOCAL_DEMO=1
uvicorn hosted_api.local_demo:factory --factory --host 127.0.0.1 --port 8019 --workers 1
```

Mo `http://127.0.0.1:8019/`, nhan link **Step 20 - evaluate synthetic detection quality** hoac mo `http://127.0.0.1:8019/demo/evaluation`.

Bang tong hop hien confusion matrix, Precision/Recall/F1, va cac tinh huong false positive/false negative. Moi lan mo trang, code dung **DemoStore moi trong RAM**. Khong lam thay doi demo key, events hay alerts dang hien thi o trang chinh.

Neu lo `Invalid form origin` o Buoc 19, xac nhan file `hosted_api/local_demo.py` la ban da sua Referrer-Policy `same-origin` truoc khi ap patch.

## 4. Kiem thu va preflight

```bash
python -m unittest discover -s tests -p test_step20_evaluation.py -v
python -m unittest discover -s tests -p test_step19_demo.py -v
python -m unittest discover -s tests -v
python -m scripts.step20_preflight
python -m scripts.step19_preflight
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
git diff --check
```

Cac bai Postgres integration duoc bo qua khi khong co TEST DSNs. Chung phai PASS tren CI job PostgreSQL 17 cua GitHub truoc merge.

## 5. Commit va PR

```bash
git status
git add README.md .github/workflows/ci.yml hosted_api/local_demo.py \
  hosted_api/demo_evaluation.py scripts/step20_evaluate.py \
  scripts/step20_preflight.py tests/test_step20_evaluation.py \
  docs/HUONG_DAN_BUOC_20.md docs/STEP20_EVALUATION_LIMITATIONS.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: add offline synthetic detection evaluation and reports"
git push -u origin feat/synthetic-detection-evaluation-step20
```

Tao PR vao `main` va doi unit tests Python 3.12/3.13, NGINX smoke va PostgreSQL RLS CI jobs PASS truoc merge. Khong commit DSN, demo tokens, log that hay ket qua bao mat chua duoc phe duyet.

## 6. Khi can quay lui

Revert commit Buoc 20 tren branch/PR. Khong co migration PostgreSQL hay thay doi schema, khong co service moi, va data local demo hien co khong bi thay doi. API localhost `8019` va Neon staging giu nguyen ranh gioi.
