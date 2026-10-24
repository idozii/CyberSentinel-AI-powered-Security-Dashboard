# CyberSentinel - Bước 5: Dataset mở rộng + ML baseline

## Phạm vi

Đây là bản **lab prototype**. Các số đo từ simulated traffic **không** chứng minh mô hình phát hiện tấn công thực tế. Bộ dữ liệu hiện tại chỉ gồm 2 windows, nên **không được train trực tiếp**. Bước này tạo thêm các *phiên mô phỏng độc lập* và benchmark có train/validation/test theo `simulation_run_id`.

File mới:

- `scripts/run_lab_experiments.py`: sinh nhiều phiên `benign`, `brute-force`, `scan`, `mixed` trên `127.0.0.1:8080`, ghi manifest, tái dùng pipeline collector → ETL → label join → feature engineering.
- `scripts/train_detector.py`: Isolation Forest train trên **benign train only**, hiệu chỉnh threshold bằng **benign validation only**, đánh giá trên holdout test; kèm fixed rule baseline.
- `tests/test_step5_ml.py`: 10 bài kiểm thử.
- `requirements-ml.txt`: thư viện ML.
- `docs/HUONG_DAN_BUOC_5.md`: file này.

Không sửa các file gốc `train_model.py`, `attack_replay.py`, `model_features.py`. Tất cả kết quả sinh ra nằm trong `simulations/runtime/processed/` và đã được `.gitignore`.

## 5.1. Tạo nhánh mới

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/lab-ml-baseline
```

Nếu `git status` có file đang sửa chưa commit, **không** chuyển nhánh trước khi sao lưu/commit/stash có chủ đích.

Giải nén ZIP tại root repository (cùng cấp `scripts/`, `tests/`, `simulations/`):

```bash
unzip -l ~/Downloads/CyberSentinel_Buoc_5_ML_Baseline.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_5_ML_Baseline.zip -d .
```

## 5.2. Cài thư viện ML trong virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-ml.txt
```

Venv `.venv/` đã nằm trong `.gitignore`.

## 5.3. Unit tests

```bash
python -m unittest discover -s tests -v
```

Kỳ vọng có **41 tests PASS** (31 tests trước đó + 10 tests mới). Đừng tiếp tục nếu có lỗi.

## 5.4. Chạy Docker local lab

```bash
docker compose -f simulations/docker-compose.yml up --build -d --wait
curl --noproxy '*' -i http://127.0.0.1:8080/health
```

Cần HTTP 200 và header `X-CyberSentinel-Request-ID`. Nếu có 502, kiểm tra:

```bash
docker compose -f simulations/docker-compose.yml ps -a
docker compose -f simulations/docker-compose.yml logs --tail=60 webapp proxy
```

## 5.5. Sinh dữ liệu mở rộng qua pipeline THỰC của lab

```bash
python -m scripts.run_lab_experiments --runs-per-class 40 --seed 42
```

- 4 loại session × 40 = **160 phiên**; tổng số HTTP requests lớn hơn 160 do mỗi phiên có nhiều requests.
- Các thông số `attempts`, `concurrency`, `source_ip` biến thiên có seed.
- Chỉ cho phép HTTP tới localhost/loopback; không follow redirects.
- Output nằm trong `simulations/runtime/processed/step5_<time>_<suffix>/`.
- Nếu status trả về khác kỳ vọng (200/401/404), script dừng để tránh đưa telemetry sai vào training.
- Có thể thử nhanh bằng `--runs-per-class 20` rồi dùng 40 cho báo cáo cuối.

Ghi nhận đường dẫn phiên mới nhất (chạy khi script trên đã kết thúc thành công):

```bash
RUN_DIR=$(find simulations/runtime/processed -maxdepth 1 -type d -name 'step5_*' | sort | tail -n 1)
echo "$RUN_DIR"
ls -lh "$RUN_DIR/labeled.csv" "$RUN_DIR/window_features.csv" "$RUN_DIR/data_summary.json"
cat "$RUN_DIR/data_summary.json"
```

Kỳ vọng:
- `matched_labeled_events` bằng `simulation_requests`
- `manifest_records_without_event` bằng 0
- đủ benign, brute-force, scan và mixed windows; số windows không nhất thiết bằng 160 vì phiên có thể băng qua ranh giới phút
- các dòng log cũ có thể nằm trong `events.csv`, nhưng phải được gắn `unlabeled` và bị loại khi sinh windows.

## 5.6. Huấn luyện Isolation Forest và rule baseline

```bash
python -m scripts.train_detector \
  --input "$RUN_DIR/window_features.csv" \
  --output-dir "$RUN_DIR/ml_results" \
  --seed 42 --target-fpr 0.05 --trees 200
```

Các tập train/validation/test được tách **theo phiên simulation_run_id** và phân bổ theo nhóm kịch bản (xấp xỉ 60/20/20). Mọi window của cùng một run phải vào cùng một tập. Các kịch bản của cùng một *loại* có template lặp lại giữa các tập; đây là hạn chế hiện chưa giải quyết.

Isolation Forest chỉ fit trên benign windows ở train. Threshold được lấy từ quantile của anomaly scores trên **benign validation**; test set được dùng đúng một lần cuối cùng để báo cáo. Rule baseline là heuristic cố định, không hiệu chỉnh trên test.

Kết quả:

```bash
cat "$RUN_DIR/ml_results/metrics.json"
head -n 6 "$RUN_DIR/ml_results/predictions.csv"
cat "$RUN_DIR/ml_results/split_manifest.json"
```

- `metrics.json`: confusion matrix qua TN/FP/FN/TP; precision/recall/F1/false-positive rate; **Average Precision (AP)** của anomaly scores.
- `predictions.csv`: dự đoán và anomaly scores ở validation và test.
- `split_manifest.json`: các run IDs của từng tập (kiểm tra không trùng).
- `isolation_forest.joblib`: mô hình local; **chỉ load model từ nguồn bạn tin cậy**, vì joblib/pickle có thể thực thi code khi load.

Nếu script thông báo **Not enough independent runs**, dùng thêm các phiên lab; **không** giảm các điều kiện tối thiểu chỉ để có điểm số.

## 5.7. Hoàn tất / GitHub

Chỉ commit code và tài liệu, không commit logs, features CSV, model, manifest, raw data.

```bash
python -m unittest discover -s tests -v
git status
git add scripts/run_lab_experiments.py scripts/train_detector.py tests/test_step5_ml.py requirements-ml.txt docs/HUONG_DAN_BUOC_5.md
git diff --cached --stat
git commit -m "feat: add local lab ML baseline and run-aware evaluation"
git push -u origin feat/lab-ml-baseline
```

Mở Pull Request vào `main`, review rồi merge sau khi xác minh kết quả chạy thực tế.

```bash
docker compose -f simulations/docker-compose.yml down
```

## Điều cần đưa vào README/report

- Data source: **controlled single-host lab**, không phải UNSW-NB15/NSL-KDD.
- Label: scenario manifest được join theo NGINX request ID; `unlabeled` không xem là benign.
- Model: Isolation Forest; 14 numeric features; baseline rule.
- Split: theo simulation run; seed; train/validation/test; validation calibration.
- Metrics: test confusion matrix, precision, recall, F1, FPR, AP và recall mỗi attack type.
- Limitations: simulated traffic quá sạch; benign thiếu lỗi xác thực bình thường; scanning lặp lại 8 paths; template cùng loại xuất hiện cả train và test; không đánh giá generalization/cross-dataset/real-time; chưa phải SOC-ready.

**Gửi lại cho ChatGPT:** output cuối của `run_lab_experiments`, output `train_detector`, các file metrics/split nếu cần; và `git status` trước khi commit.
