# CyberSentinel - Buoc 21: Offline Detection Tuning va Quality Gate

## Muc tieu

Buoc 20 cho ket qua synthetic micro Precision, Recall va F1 = 66.67%.
Buoc 21 dung 81 cau hinh nguong (moi nguong +/-1) de minh hoa qua khop
(overfitting) tren 14 kich ban GAN NHAN THU CONG. Day KHONG phai do luong
hieu nang tren luu luong thuc, khong su dung dataset ML, khong tu ap nguong.

- 8 kich ban development de lua chon candidate bang F1, sau do precision,
  false positives va khoang cach voi baseline de pha hoa.
- 6 kich ban synthetic validation duoc de rieng; KHONG dung de chon nguong.
- Luong baseline duoc chay bang DemoStore that, sau do so sanh voi
  shadow counter evaluator de phat hien sai khac trong implement.
- Pin checksum cho labels + rules, va pin confusion matrix Step 20 trong CI.
- Bao cao JSON + Markdown duoc tao ben ngoai Git, voi quyen 0700/0600.

## 1. Ap dung file ZIP

Dang o repo CyberSentinel cua ban; truoc khi switch, bao dam `git status`
khong co thay doi quan trong chua luu:

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/detection-tuning-quality-gate-step21
unzip -o ~/Downloads/CyberSentinel_Buoc_21_Quality_Gate.zip -d .
source /home/idozii/envs/ds/bin/activate
```

## 2. Chay tests va benchmark

```bash
python -m unittest discover -s tests -p test_step21_tuning.py -v
python -m scripts.step21_preflight
python -m scripts.step21_quality_gate
python -m unittest discover -s tests -v
python -m scripts.release_audit
```

Ket qua tham khao:

| Split | Baseline F1 | Candidate F1 |
|---|---:|---:|
| Development (8 synthetic cases) | 66.67% | 100.00% |
| Validation (6 synthetic cases) | 66.67% | 33.33% |

Nguong shadow candidate: login 4 (baseline 5), 404 9 (baseline 8),
5xx 5, volume 40. **Khong ap dung candidate vao he thong that.**

## 3. Xuat bao cao offline

Dung ten thu muc chua ton tai va nam ben ngoai repo:

```bash
python -m scripts.step21_quality_gate --output-dir /tmp/cyber-step21-report
```

File tao ra: `step21_tuning.json`, `step21_tuning.md`.
Chay lai voi mot duong dan khac, vi script co tinh chan ghi de bao cao cu.

## 4. Xem ket qua trong localhost Dashboard

```bash
export CYBERSENTINEL_LOCAL_DEMO=1
uvicorn hosted_api.local_demo:factory --factory --host 127.0.0.1 --port 8019 --workers 1
```

Mo `http://127.0.0.1:8019/demo/tuning`, hoac nhan Step 21 tren demo dashboard.
Page chi doc, khong reset demo agent key, khong dong vao Neon.

## 5. Commit va PR

```bash
git diff --check
git status
git add .github/workflows/ci.yml README.md hosted_api/local_demo.py \
  hosted_api/demo_tuning.py scripts/step21_quality_gate.py scripts/step21_preflight.py \
  tests/test_step21_tuning.py docs/HUONG_DAN_BUOC_21.md \
  docs/STEP21_QUALITY_LIMITATIONS.md docs/ROADMAP_TO_PRODUCT.md
git diff --cached --stat
git diff --cached --check
git commit -m "feat: add offline detection tuning and synthetic regression gate"
git push -u origin feat/detection-tuning-quality-gate-step21
```

Tao PR voi base `main`. Cho CI Python 3.12, 3.13 va PostgreSQL RLS PASS.
**Khong commit secret, DSN, file bao cao chua duoc review, hoac log thuc.**

## 6. Rollback

Bai toan chi them code Python va UI read-only. Khong co database migration,
khong co infrastructure change, khong doi nguong phat hien cua live detectors.
Neu can, revert commit Buoc 21. Khong can rollback du lieu Neon.
