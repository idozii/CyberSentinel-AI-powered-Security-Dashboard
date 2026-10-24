# CyberSentinel - Bước 10: Owner Accounts & DNS TXT Domain Verification

## 1. Kết quả và giới hạn

Bước 10 bổ sung **LOCAL-ONLY Owner Onboarding Prototype** song song với Public Security Checker hiện có. Phần này có:

- Tạo tài khoản email + mật khẩu (mật khẩu băm Argon2id, không lưu plaintext).
- Đăng nhập bằng bearer token ngẫu nhiên ẩn khỏi URL, máy chủ chỉ lưu SHA-256 hash; token tự hết hạn sau 8 giờ và có thể logout.
- Khoá tạm tài khoản sau 5 lần nhập sai mật khẩu (15 phút) để thử nghiệm cơ chế chống đoán mật khẩu.
- Danh sách domains thuộc từng tài khoản; người khác không thể đọc, xoay vòng challenge, xoá, hoặc verify thay.
- Tạo DNS TXT challenge 32 bytes ngẫu nhiên, chỉ trả plaintext challenge **một lần lúc tạo/rotate** và lưu hash tại DB, hạn 24 giờ.
- Chỉ xác nhận domain sau khi DNS TXT trả **đúng proof**; tránh chiếm chỗ domain bằng các claim pending và chỉ cho một owner verified tại một thời điểm.
- Có thể xoá claim để thu hồi quyền liên kết domain.
- Giao diện Streamlit portal chạy riêng tại localhost:8503; Owner API tại localhost:8002; SQLite riêng trong đường dẫn bị `.gitignore`.

**Chưa có** agent, telemetry ingestion, alerting, email verification, MFA, password reset, OAuth/OIDC, durable hosted DB, audit trail hoàn chỉnh, reverse proxy công khai, WAF, egress restrictions hay cơ chế chống abuse quy mô Internet. Vì vậy **KHÔNG deploy Owner API/Portal ra public internet hoặc Streamlit Community Cloud** ở Bước 10. Không dùng tài khoản/mật khẩu thật quan trọng trong bản demo local này.

## 2. Tạo nhánh và giải nén

Chạy từ repository root (nơi có `README.md`, `dashboard/`, `scripts/`):

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/owner-onboarding-step10

unzip -l ~/Downloads/CyberSentinel_Buoc_10_Owner_Onboarding.zip
unzip -o ~/Downloads/CyberSentinel_Buoc_10_Owner_Onboarding.zip -d .
```

Nếu có uncommitted edits, lưu lại trước khi chuyển nhánh. Không giải nén vào `owner_api/` hoặc `dashboard/`; ZIP chứa các path đầy đủ. File `.gitignore`, `.github/workflows/ci.yml` và `scripts/release_audit.py` sẽ được cập nhật; kiểm tra staged diff trước khi commit.

## 3. Install và kiểm thử

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m compileall -q owner_api owner_portal
```

Trên repository đầy đủ sau Bước 9 kỳ vọng **115 tests** (= 93 cũ + 22 tests mới). Nếu con số khác, đọc danh sách tests: không giảm kỳ vọng chỉ để có PASS. Trường hợp `argon2` hoặc `dns` missing, cài đúng `requirements-owner.txt`.

## 4. Khởi động API và portal

**Terminal 1** - Owner API:

```bash
source .venv/bin/activate
uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
```

**Terminal 2** - Portal:

```bash
source .venv/bin/activate
streamlit run owner_portal/app.py --server.address 127.0.0.1 --server.port 8503
```

Mở **http://127.0.0.1:8503**, API docs tại **http://127.0.0.1:8002/docs**.

Health check:

```bash
curl --noproxy '*' http://127.0.0.1:8002/owner/health
```

Kỳ vọng:

```json
{"status":"ok","mode":"local-owner-onboarding","live_monitoring":false}
```

Không chạy `--host 0.0.0.0`. API chỉ chấp nhận loopback và host đã cho phép trong development, nhưng điều đó **không** thay thế firewall/authorization đúng cách nếu đặt sau reverse proxy.

## 5. Thử chức năng

1. **Create local account:** đăng ký với email demo và mật khẩu riêng dài ít nhất 12 ký tự. Không dùng password quan trọng của bạn.
2. **Sign in:** đăng nhập, xem email hiện tại và danh sách domain rỗng.
3. **Add domain:** nhập **một public DNS hostname do bạn kiểm soát**, ví dụ `my-site.example.org` *chỉ nếu đó thực sự là domain bạn quản lý*. Chấp nhận tên hostname ASCII, không chấp nhận IP, localhost, URL hoặc cổng tùy ý.
4. **Publish DNS TXT:** Portal đưa một cặp `TXT name` và `TXT value`. Thêm bản ghi đúng vào nhà cung cấp DNS của bạn; bản ghi có dạng `_cybersentinel-verify.<your-domain>` và value là `cybersentinel-verification=<random-token>`. Một số DNS control panel chỉ cần phần tên tương đối: `_cybersentinel-verify`.
5. **Verify DNS:** sau khi bản ghi được DNS public nhìn thấy, bấm Verify DNS. Nếu thiếu/không khớp sẽ nhận 422; nếu DNS gặp vấn đề sẽ 503; challenge hết hạn trả 409 và có thể Rotate.
6. **Remove claim:** chủ tài khoản có thể xoá xác minh. Nếu không có domain do bạn sở hữu, **không cần cố xác minh domain của người khác**: các unit tests có fake DNS resolver kiểm tra đầy đủ positive path mà không gửi request thật.
7. **Logout:** phiên hiện tại bị huỷ ngay.

Quản lý TXT proof theo cơ chế riêng của CyberSentinel, **không phải ACME DNS-01 của TLS certificate**, dù cùng ý tưởng dùng TXT record để chứng minh DNS control.

## 6. Chính sách dữ liệu local

SQLite mặc định ở `simulations/runtime/owner/owner_local.sqlite3` (không commit). Database chứa email và password hashes, hashed session tokens, DNS challenge hashes, verified-domain relations. POSIX file permission: directory 700, database 600. Không đưa vào ZIP, repo, screenshot công khai hoặc cộng tác với dữ liệu thật. Nếu xoá DB sẽ mất toàn bộ các tài khoản và claims local, không ảnh hưởng các lab artifacts Steps 1-9.

Kiểm tra Git không chứa dữ liệu tài khoản:

```bash
git status --short
git check-ignore -v simulations/runtime/owner/owner_local.sqlite3
python -m scripts.release_audit
```

## 7. Commit / PR

```bash
git status
git diff --check
git add \
  owner_api/__init__.py owner_api/main.py owner_api/store.py owner_api/dns_verify.py \
  owner_portal/app.py requirements-owner.txt tests/test_step10_owner.py \
  docs/HUONG_DAN_BUOC_10.md docs/OWNER_PLATFORM_ROADMAP.md \
  .github/workflows/ci.yml .gitignore scripts/release_audit.py

git diff --cached --stat
git diff --cached --name-status
python -m scripts.release_audit

git commit -m "feat: add local owner accounts and DNS domain verification"
git push -u origin feat/owner-onboarding-step10
```

Tạo PR vào `main`; ba jobs GitHub CI (Python 3.12, 3.13, Docker) phải PASS. **Không cần merge nếu có lỗi.** Việc bạn chạy local và PR thành công **không** có nghĩa đã có public owner authentication service.

## 8. Điều cần bổ sung trước khi public owner monitoring

- External managed authentication/OIDC, verified emails, password reset, MFA, bot protection; central rate limiting. Tránh lưu password/account trong instance tạm.
- Persistent multi-tenant database (PostgreSQL) và object storage, migrations, retention/deletion, encrypted backups, audit logs.
- Domain lifecycle: ownership re-verification, multi-team permissions, transfers, ownership disputes; DNS checks qua hạ tầng ổn định.
- HTTPS ingress, proxy trust model, server-side tenancy enforcement, abuse and SSRF tests, secret management and rotation.
- Agent API key scoped riêng cho verified service, key revocation/rotation, write-only event upload, quotas và schema validation.
- Detection pipeline sử dụng realtime window keys (`service_id`, IP buckets, window time), không bao giờ phụ thuộc lab `simulation_run_id`.
- Khả năng dùng dữ liệu thật cần consent, thông tin riêng tư được xử lý tối thiểu, triage & false positive evaluation.

Xem thêm `docs/OWNER_PLATFORM_ROADMAP.md`.
