# CyberSentinel - Bước 7: FastAPI + Streamlit Experiment Explorer

## Phạm vi và bảo mật

- Dashboard **chỉ đọc** dữ liệu thí nghiệm đã lưu: `data_summary.json`, `window_features.csv`, `ml_results/metrics.json`, `predictions.csv` và `robustness_report.json`.
- Không khởi chạy mô hình để dự báo thời gian thực, không nạp `.joblib`/pickle, không truy cập mục tiêu ngoài localhost, không có chức năng tấn công.
- Địa chỉ mặc định của API: `http://127.0.0.1:8001`; Streamlit: `http://127.0.0.1:8501`. **Không dùng `--host 0.0.0.0` hoặc port forwarding/public deployment** với dữ liệu lab này khi chưa có xác thực, phân quyền và xử lý dữ liệu cá nhân.
- IP nguồn trong demo có thể đến từ header giả lập (`X-Forwarded-For`), **không đáng tin cậy để quy kết danh tính người dùng**.
- Model vẫn có scanning recall 0% trong test Bước 5. Không diễn giải như hệ thống IDS sẵn sàng triển khai.

## 7.1 Tạo nhánh

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/local-security-dashboard
```

Giải nén ZIP tại **repo root**, không phải trong `scripts` hoặc `docs`. Nên xem danh sách trước khi giải nén:

```bash
unzip -l ~/Downloads/CyberSentinel_Buoc_7_Dashboard.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_7_Dashboard.zip -d .
```

Bộ file khôi phục tài liệu Bước 4-5 vì chúng bị xóa ngoài ý muốn tại commit trước.

## 7.2 Cài dependencies

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt
python -m pip install -r requirements-dashboard.txt
python -m unittest discover -s tests -v
```

Kỳ vọng: **62 tests** = 51 cũ + 11 tests API mới. Không cần Docker để xem lại thí nghiệm đã lưu.

## 7.3 Khởi chạy FastAPI

Terminal số 1 (tại repo root, có kích hoạt `.venv`):

```bash
uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8001
```

Kiểm tra:

```bash
curl --noproxy '*' http://127.0.0.1:8001/api/health
curl --noproxy '*' http://127.0.0.1:8001/api/runs
```

Swagger: `http://127.0.0.1:8001/docs`. Nếu API trả `runs: []`, đảm bảo thư mục `simulations/runtime/processed/step5_*` vẫn tồn tại và có `window_features.csv`.

## 7.4 Khởi chạy Streamlit

Terminal số 2 (cùng repo root):

```bash
source .venv/bin/activate
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

Mở `http://127.0.0.1:8501`. Chọn phiên chạy như `step5_20261024T062626Z_b73020` trong sidebar.

Tab Overview: số request, label coverage, windows, phân bố scenario.
Tab Traffic Explorer: 14 features theo cửa sổ và lọc kịch bản.
Tab Model Evaluation: F1/recall/FPR/AP, confusion counts, anomaly scores của holdout test và baseline.
Tab Robustness: split integrity, kết quả stress-test feature-space nếu có báo cáo từ Bước 6.

Để tạo báo cáo Robustness nếu chưa có (chỉ với model do chính bạn tạo và tin cậy; không nạp model bên ngoài):

```bash
RUN_DIR="simulations/runtime/processed/step5_20261024T062626Z_b73020"
python -m scripts.audit_detector_robustness \
  --input "$RUN_DIR/window_features.csv" \
  --ml-results "$RUN_DIR/ml_results" \
  --output "$RUN_DIR/ml_results/robustness_report.json"
```

## 7.5 CI và commit

Đã chỉnh workflow `.github/workflows/ci.yml` để cài thêm `requirements-dashboard.txt` khi chạy Python unit tests; CI Docker smoke cũ vẫn giữ nguyên.

```bash
python -m unittest discover -s tests -v
python -m compileall -q dashboard_api dashboard tests

git status
git diff --check
git add dashboard_api/ dashboard/ .streamlit/config.toml tests/test_step7_dashboard_api.py \
  requirements-dashboard.txt .github/workflows/ci.yml \
  docs/HUONG_DAN_BUOC_4.md docs/HUONG_DAN_BUOC_5.md docs/HUONG_DAN_BUOC_7.md

git diff --cached --stat
git commit -m "feat: add read-only local FastAPI and Streamlit experiment dashboard"
git push -u origin feat/local-security-dashboard
```

Mở PR -> `main`, kiểm tra cả 3 CI jobs PASS rồi review/merge. Không commit các file sinh ra trong `simulations/runtime/processed` hoặc model `.joblib`.

## 7.6 Giới hạn còn lại / Bước 8

- Read-only retrospective dashboard; không phải live SIEM, không có authentication / session / rate limiting, chưa hỗ trợ API public.
- Dataset hoàn toàn mô phỏng, fixed-rule baseline rất dễ đạt 100% vì các template quá đơn giản.
- Audit là giả định thay đổi các feature, không phải external validation.
- Chưa có ứng dụng real-time hay lưu cơ sở dữ liệu. Để tiến đến sản phẩm trình diễn hoàn chỉnh, cần thêm dữ liệu benign/attack đa dạng, đánh giá ngoài tập lab, và sau đó mới xây ingestion streaming với privacy/security safeguards.
