# CyberSentinel — Bước 6: Robustness Audit + GitHub Actions CI

## Mục tiêu

Đây là **research/educational prototype trên traffic mô phỏng**. Bước 5 đã có 160 runs, nhưng Isolation Forest bỏ sót nhiều scan windows. Bước 6 kiểm tra tính toàn vẹn của kết quả model đã fit và thử một số biến đổi *counterfactual* (giả định trên vector features), không chỉnh ngưỡng hay huấn luyện lại trên tập test. Đồng thời, thêm CI chạy unit tests trên Python 3.12/3.13 và Docker localhost smoke end-to-end.

### File mới (chỉ thêm, không ghi đè code Bước 5)

- `scripts/audit_detector_robustness.py` — kiểm tra split disjoint, train/validation/test coverage, threshold reproducible từ benign validation, đối chiếu saved test metrics, stress-test đã đóng băng mô hình.
- `tests/test_step6_robustness.py` — 10 unit tests mới; gồm ba lỗi dữ liệu bị từ chối và test end-to-end không làm thay đổi model artifact.
- `.github/workflows/ci.yml` — job Python matrix + job Docker localhost smoke.
- `docs/HUONG_DAN_BUOC_6.md` — hướng dẫn này.

### Giới hạn quan trọng

- Counterfactual được tạo từ **features có sẵn trong test set**, KHÔNG phải sự kiện HTTP mới, KHÔNG phải external validation và KHÔNG đo hiệu quả triển khai thực tế.
- **Không** chọn lại model, threshold hay feature set bằng các số đo từ Bước 6; nếu thay đổi hệ thống cần một holdout mới/đánh giá độc lập.
- Chỉ load file `.joblib` **do chính bạn tạo**; joblib dựa trên pickle có nguy cơ thực thi code khi load.
- Bài smoke Docker CI chạy trên loopback `127.0.0.1`, không hướng tới IP Internet.
- Script audit Bước 6 không liên quan tới Docker: cần các artifact Bước 5 tại máy bạn.

## 6.1. Đồng bộ GitHub và tạo branch

Trong thư mục gốc repository:

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/robustness-ci
```

Nếu có thay đổi chưa commit, lưu lại có chủ ý trước khi chuyển branch. PR #6 Bước 5 đã merge vào `main`.

## 6.2. Giải nén tại root

```bash
unzip -l ~/Downloads/CyberSentinel_Buoc_6_Robustness_CI.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_6_Robustness_CI.zip -d .
```

Chỉ nên xuất hiện thêm đúng 4 file nêu trên. Không giải nén bên trong `scripts/`.

## 6.3. Kiểm tra dependencies và unit tests

Nếu bạn đã có `.venv` từ Bước 5:

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt
python -m unittest discover -s tests -v
```

Nếu chưa có `.venv`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-ml.txt
python -m unittest discover -s tests -v
```

Kỳ vọng trên full repo: **51 tests** (41 cũ + 10 mới) PASS. Tác giả kiểm thử bộ file mới trên bản sao repo cục bộ có 46 tests tổng và tất cả PASS; chưa kiểm tra runner GitHub thực tế.

## 6.4. Chạy robustness audit trên model Bước 5

Dùng **đúng run có model đã train thành công** từ Bước 5. Từ output của bạn, đó là:

```bash
RUN_DIR="simulations/runtime/processed/step5_20261024T062626Z_b73020"

ls -lh "$RUN_DIR/window_features.csv" \
       "$RUN_DIR/ml_results/metrics.json" \
       "$RUN_DIR/ml_results/split_manifest.json" \
       "$RUN_DIR/ml_results/isolation_forest.joblib"

python -m scripts.audit_detector_robustness \
  --input "$RUN_DIR/window_features.csv" \
  --ml-results "$RUN_DIR/ml_results" \
  --output "$RUN_DIR/ml_results/robustness_report.json"
```

Script xác nhận trước khi chạy stress test:

1. Không có `simulation_run_id` trùng giữa train, validation, test; không thiếu hoặc thừa runs.
2. Threshold lưu trong model khớp với metrics và tái tạo được **chỉ từ benign validation**.
3. Holdout test metrics tái tạo được từ model không đổi, dataset và run manifest.

Nếu kiểm tra nào sai, script **dừng mà không ghi báo cáo cuối**; không tự động "sửa" model hay gán nhãn.

Ba phép thử what-if (đều trên holdout test đã biết, không tạo independent samples):

- `latency_payload_shift_all_test`: tăng latency và kích thước HTTP request, giảm response bytes — kiểm tra sensitivity của score trước biến động hạ tầng.
- `two_auth_typos_benign_only`: giả sử user bình thường nhập sai mật khẩu 2 lần — kiểm tra nguy cơ báo động giả khi benign traffic không hoàn toàn sạch.
- `reduced_attack_volume_attack_only`: giảm xấp xỉ một nửa số request và count features — kiểm tra độ nhạy với hoạt động thấp hơn. Đây chỉ là **proportional feature thinning**, không thay thế slow-attack replay thực tế.

**Không cần chạy lại 160 phiên**, không cần Docker cho audit này.

## 6.5. Xem báo cáo

```bash
cat "$RUN_DIR/ml_results/robustness_report.json"
```

Hoặc in phần tóm tắt:

```bash
python - "$RUN_DIR/ml_results/robustness_report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding='utf-8'))
print('Split integrity:', report['split_integrity'])
for name, item in [('Original test', report['reference_original_test']),
                   *report['what_if_cases'].items()]:
    print(name, 'n=', item['n_windows'],
          'IF=', item['isolation_forest'],
          'Rule=', item['fixed_rule_baseline'])
PY
```

Lưu ý FPR/precision/F1 trong trường hợp chỉ có benign hoặc attack có thể không phù hợp để so trực tiếp với metrics trên tập test đầy đủ. Nên so sánh **false positive rate** của `two_auth_typos_benign_only` với FPR bình thường, và **attack recall** của `reduced_attack_volume_attack_only` với recall bình thường.

## 6.6. Commit, tạo Pull Request và kiểm tra Actions

```bash
git status
git diff --check

git add \
  .github/workflows/ci.yml \
  scripts/audit_detector_robustness.py \
  tests/test_step6_robustness.py \
  docs/HUONG_DAN_BUOC_6.md

git diff --cached --stat
git commit -m "test: add frozen-model robustness audit and CI checks"
git push -u origin feat/robustness-ci
```

Vào GitHub → Pull requests → tạo PR từ `feat/robustness-ci` vào `main`. Theo dõi tab **Checks** hoặc **Actions**:

- `Unit tests / Python 3.12` cần PASS.
- `Unit tests / Python 3.13` cần PASS.
- `Local NGINX / webapp smoke` cần PASS (11 requests có nhãn; collector → ETL → join → windows).

CI không yêu cầu tải lên logs, model `.joblib` hay data từ máy cá nhân. Nếu CI thất bại, **không merge PR**; gửi output error để kiểm tra. Chúng tôi chưa chạy GitHub Actions trên tài khoản bạn, nên trạng thái PASS thực tế chưa được xác nhận.

Các thư mục `simulations/runtime/processed/` tiếp tục được `.gitignore`. Đừng commit model hoặc raw logs. Sau khi PR xanh và review thì merge vào `main`.

## Nên gửi lại để được kiểm tra

1. `python -m unittest discover -s tests -v` (dòng cuối số tests, `OK` hoặc lỗi).
2. Phần `split_integrity` và `what_if_cases` của `robustness_report.json`.
3. GitHub Actions Checks / lỗi CI (nếu có).
4. `git status` trước khi merge.

## Sau Bước 6

Bước 7: API + Streamlit dashboard theo hướng trình bày rõ rule-based baseline so với Isolation Forest, giải thích tại sao scan recall còn yếu; cảnh báo thật chỉ khi kết quả mô hình được đánh giá tiếp trong môi trường phù hợp. Không coi kết quả lab là đảm bảo an ninh.
