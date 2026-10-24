# CyberSentinel - Bước 9: Public Website Checker + Owner Platform Architecture

## Đã có vs chưa có

- **Đã có:** Public research showcase (Step 8), thêm màn hình **Website Checker** để đánh giá thụ động TLS và sáu tiêu chí HTTP response headers, cùng trang giới thiệu owner monitoring trong roadmap.
- **Chưa có:** User login, xác minh domain ownership, agent, event ingestion từ bên ngoài, real-time alerts, live ML predictions cho khách hàng. Tuyệt đối **không** ghi các chức năng này là đã hoạt động.

## 9.1 Tạo branch

Chạy từ thư mục gốc repository:

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/public-checker-step9
```

Nếu có thay đổi chưa commit, phải bảo toàn chúng trước khi chuyển branch.

## 9.2 Giải nén ZIP đúng thư mục

```bash
unzip -l ~/Downloads/CyberSentinel_Buoc_9_Public_Checker.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_9_Public_Checker.zip -d .
```

ZIP ghi đè **chỉ** `dashboard/public_app.py`, thêm `dashboard/site_checker.py`, `tests/test_step9_site_checker.py` và tài liệu. **Không** thay đổi `dashboard/app.py` hoặc `dashboard_api/` vốn dành cho localhost.

## 9.3 Kiểm thử

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt
python -m unittest discover -s tests -v
python -m scripts.release_audit
```

Bản sao tích hợp đã chạy **88 tests PASS**, gồm 17 tests mới. Trên repo đầy đủ, nếu vẫn có 76 tests hiện tại thì kỳ vọng **93 tests**. Kết quả phải được xác nhận từ máy và GitHub CI của bạn.

### Các kiểm tra bảo mật quan trọng

- Chặn `http://`, private/loopback literal, userinfo, port, query, path, CRLF/encoded URL.
- DNS A/AAAA: bất kỳ địa chỉ nội bộ/non-global nào đều bị từ chối, kể cả trường hợp mixed public/private.
- Kết nối đến IP đã kiểm tra, dùng domain cho `Host` + TLS SNI/certificate verification; không thực hiện DNS lần hai giữa validation và kết nối.
- Không theo HTTP redirects; HTTP 301/302/405/501 không được chấm điểm.
- Mỗi đánh giá dùng đúng **một** `HEAD /`, HTTPS/443, timeout 4 giây.
- Màn hình hiển thị không làm lộ secrets, logs, model artifacts từ pipeline lab.

## 9.4 Chạy ứng dụng tương tác tại máy

```bash
streamlit run dashboard/public_app.py --server.address 127.0.0.1 --server.port 8502
```

Mở `http://127.0.0.1:8502`, vào **Website Checker**. Thử một domain HTTPS công khai mà bạn có quyền kiểm tra thụ động, ví dụ domain do bạn quản lý. Trang không nhận đường dẫn, không scan điểm yếu, không tự follow redirects. Một số website lớn có thể không hỗ trợ `HEAD` hoặc IP-only pinning từ nền tảng hosting; kết quả **not scored** là chấp nhận được. Đừng tự động hóa request hàng loạt.

Màn hình **Owner Monitoring (Roadmap)** là thông tin định hướng, chưa có login hay live agent.

## 9.5 Commit và PR

```bash
git status
git add dashboard/public_app.py dashboard/site_checker.py tests/test_step9_site_checker.py docs/PRODUCT_ARCHITECTURE.md docs/HUONG_DAN_BUOC_9.md
git diff --cached --stat
git diff --cached --check
git commit -m "feat: add bounded public HTTPS posture checker and owner roadmap"
git push -u origin feat/public-checker-step9
```

Tạo PR vào `main`, yêu cầu CI Python 3.12/3.13 và Docker smoke đều PASS trước khi merge.

## 9.6 Deploy lên Streamlit Community Cloud

Trên `https://share.streamlit.io/`: `Create app` → chọn repo `idozii/CyberSentinel-AI-powered-Security-Dashboard`, branch `main`, entrypoint `dashboard/public_app.py`. File `dashboard/requirements.txt` đã nằm cùng thư mục entrypoint. Chọn Python 3.12 nếu có; kiểm tra cả Research Showcase và Website Checker sau deploy.

**Quan trọng:** phần checker chủ động kết nối đến domain được nhập. Đây vẫn là MVP/thử nghiệm và **chưa có rate limit toàn cục hoặc network egress firewall được xác minh**. Session limit trong Streamlit chỉ là chống lạm dụng cơ bản, có thể bị bypass. Trước khi quảng bá rộng rãi hoặc phục vụ người dùng không tin cậy ở quy mô lớn, hãy thêm global rate limiting/WAF/quota ở tầng ingress và chính sách egress ngăn truy cập mạng nội bộ. Nếu chưa có lớp bảo vệ này, nên giới hạn phạm vi beta thay vì quảng bá như scanner công khai hoàn thiện.

## 9.7 Hướng tiếp theo cho Live Monitoring

Xem `docs/PRODUCT_ARCHITECTURE.md`: Step 10 xác minh chủ sở hữu domain và tenant isolation, Step 11 agent có xác thực, Step 12 alerting + live processing. Public checker và live monitoring **không dùng chung mức độ tin cậy**; không cho một người bất kỳ gửi logs vào tài khoản domain khác.

## Gửi lại để kiểm tra

Gửi output `python -m unittest discover -s tests -v`, screenshot trang **Website Checker**, `git status`; sau khi tạo PR gửi link PR. Sau deploy gửi URL thực tế; URL không thể được dự đoán chính xác trước khi Streamlit cấp.
