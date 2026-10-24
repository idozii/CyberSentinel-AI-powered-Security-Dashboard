# CyberSentinel — Bước 8: Portfolio, Documentation & Final Release Audit

> **Phạm vi:** khôi phục tài liệu đã bị mất trên `main`, cập nhật README phản ánh code thực tế, ghi lại ML metrics đã đo và thêm release audit chỉ đọc. Không thay đổi mô hình, threshold, API hoặc dữ liệu Bước 5–7. Bước 8 không biến prototype thành IDS production.

## 8.0 Kiểm tra Bước 7

PR #8 (`feat/local-security-dashboard`) đã merge vào `main` trên GitHub. Cả ba CI jobs trên PR #8 (Python 3.12, Python 3.13, Docker smoke) đã PASS. Sau merge, repository chứa `dashboard/`, `dashboard_api/`, `tests/test_step7_dashboard_api.py`, `requirements-dashboard.txt` và `.github/workflows/ci.yml`.

**Lưu ý:** hiện tại `main` không có thư mục `docs/` (các tài liệu Bước 4–7 đã bị xóa trong quá trình commit trước). ZIP Bước 8 khôi phục đúng bốn tài liệu đó.

## 8.1 Đảm bảo đang ở repository root và working tree sạch

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c docs/portfolio-release-audit
```

Nếu `git status` có thay đổi chưa commit, dừng trước khi chuyển branch và kiểm tra các thay đổi đó. Không dùng `git reset --hard` để giải quyết nhanh.

## 8.2 Giải nén file ZIP Bước 8

Tải `CyberSentinel_Buoc_8_Portfolio_Release.zip` vào `~/Downloads` rồi chạy **trong repository root**:

```bash
unzip -l ~/Downloads/CyberSentinel_Buoc_8_Portfolio_Release.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_8_Portfolio_Release.zip -d .
```

Bộ file gồm README mới, `.github/workflows/ci.yml` cập nhật, script audit, tests và toàn bộ thư mục `docs/`. Không có logs, model, `.env`, dữ liệu thực hay ảnh nhạy cảm.

## 8.3 Kiểm tra đơn vị và static release audit

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt
python -m unittest discover -s tests -v
python -m scripts.release_audit
```

**Kỳ vọng:** 62 unit tests cũ + 7 tests mới = **69 PASS** trên repository đầy đủ của bạn, nếu code cũ không đổi. Release audit cần in `"status": "pass"`.

Audit chỉ kiểm tra các file cần thiết, một số quy tắc `.gitignore`, và các đường dẫn đang theo dõi bởi `git ls-files` để phát hiện một số loại bí mật/model/log bị commit nhầm. Nó không quét nội dung để tìm API keys, không phải SAST, không xác nhận ứng dụng an toàn cho Internet.

## 8.4 Đọc lại tài liệu trước khi commit

- `README.md`: trạng thái triển khai thực tế, hướng dẫn chạy, sơ đồ hệ thống, metrics và contributors.
- `docs/PROJECT_ARCHITECTURE.md`: data flow, trust boundaries và 14 features.
- `docs/EXPERIMENT_RESULTS.md`: số liệu 2,678 requests, 160 windows, test F1 0.4516 và scanning recall 0.
- `docs/SECURITY_AND_LIMITATIONS.md`: localhost-only, IP spoofing, nguy cơ model overfit, không có xác thực nếu public.
- `docs/REPRODUCIBILITY.md`: từ môi trường mới đến sinh dataset, train, robustness audit, dashboard.
- `docs/PORTFOLIO_DEMO.md`: kịch bản demo, checklist screenshot và phần thảo luận về giới hạn ML.
- `docs/HUONG_DAN_BUOC_4.md` đến `_7.md`: các tài liệu cũ được khôi phục.

Các metrics trong báo cáo dựa trên output đã chạy của **một phiên thí nghiệm ngày 24/10/2026**; chúng không được đóng gói trong ZIP dưới dạng dataset. Khi dùng lại, ghi rõ kết quả là *controlled synthetic local simulation*.

## 8.5 Kiểm tra nội dung trước khi push

```bash
git status
git diff --check

git add README.md \
  .github/workflows/ci.yml \
  scripts/release_audit.py \
  tests/test_step8_release.py \
  docs/

git diff --cached --stat
git diff --cached --name-status
python -m scripts.release_audit
```

Bộ diff **không được** chứa `simulations/runtime/logs`, `simulations/runtime/raw`, `simulations/runtime/processed`, `.env`, `.venv`, `.joblib` hay ảnh/private files không chủ ý. Nếu một file nhạy cảm đã bị Git track, `.gitignore` không tự động xóa nó khỏi index; cần xử lý riêng trước khi push.

```bash
git commit -m "docs: complete portfolio report and add release audit"
git push -u origin docs/portfolio-release-audit
```

Mở Pull Request `docs/portfolio-release-audit → main`, review và chỉ merge khi jobs Python 3.12, Python 3.13 và Docker smoke đều thành công. Nhờ Step 8, các Python jobs sẽ thêm `python -m scripts.release_audit`.

## 8.6 Đối chiếu sau merge

```bash
git switch main
git pull --ff-only origin main
python -m unittest discover -s tests -v
python -m scripts.release_audit
git status
```

## 8.7 Có thể hoàn thiện thêm sau Bước 8

- Bổ sung **screenshots thật** được chụp từ dashboard local, cắt riêng phần ứng dụng và loại bỏ các thông tin cá nhân. Nếu chưa có file ảnh, không thêm đường dẫn ảnh vào README tránh link hỏng.
- Không chỉ nhìn vào F1 trên lab. Nếu định nghiên cứu tiếp, hãy tạo dataset mới có nhiều trường hợp benign lỗi đăng nhập và scan variants chưa từng xuất hiện, dùng template-disjoint holdout và báo cáo confidence intervals.
- Giữ portfolio chính xác: API hiện là **read-only offline experiment explorer**, không phát hiện/alert thời gian thực, không có authentication/RBAC, không mở public.

**Gửi lại để xác minh:** output `python -m scripts.release_audit`, 69 tests cuối, `git status`, link PR và tình trạng 3 jobs trên GitHub Actions.
