# CyberSentinel - Buoc 41: Database tenant login isolation (CI-only proof)

**Muc tieu:** Chung minh su khac nhau giua `cs.actor_id` do shared runtime role
co the tu dat va RLS rang buoc bang `session_user` cua login role rieng tung tenant.

**Pham vi:** Chi prototype tren PostgreSQL 17 tam thoi trong GitHub Actions.
KHONG co migration 003, KHONG sua Neon, KHONG doi API, KHONG deploy public.

## 1. Tao nhanh va cai ban va

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/tenant-role-isolation-poc-step41
unzip -o ~/Downloads/CyberSentinel_Buoc_41_Tenant_Role_PoC.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m scripts.install_step41
```

Chi chay tren working tree sach, kiem tra `git diff` truoc commit.

## 2. Kiem thu offline

```bash
python -m unittest discover -s tests -p test_step41_offline.py -v
python -m scripts.step41_preflight
python -m scripts.step41_role_boundary
python -m scripts.step41_release
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
```

Khi khong co ephemeral PostgreSQL, `test_step41_role_isolation_pg.py` se SKIP.
Khong set `GITHUB_ACTIONS` / `CYBERSENTINEL_ISOLATED_PG_CI` bang tay de
chay tren database thong thuong; bai test tao roles va schema, roi xoa chung.

## 3. Tao PR de GitHub CI kiem chung PostgreSQL 17

```bash
git diff --check
git status
git add README.md .github/workflows/ci.yml \
  scripts/install_step41.py scripts/step41_role_boundary.py \
  scripts/step41_preflight.py scripts/step41_release.py \
  tests/test_step41_offline.py tests/test_step41_role_isolation_pg.py \
  docs/HUONG_DAN_BUOC_41.md docs/STEP41_TENANT_ROLE_SECURITY.md
git diff --cached --check
git diff --cached --stat
git commit -m "test: prototype PostgreSQL tenant-bound login isolation"
git push -u origin feat/tenant-role-isolation-poc-step41
```

PR:
https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/compare/main...feat/tenant-role-isolation-poc-step41?expand=1

## 4. Tieu chi pass

- Offline preflight va release gate PASS, public beta BLOCKED.
- PostgreSQL 17 CI: 3 integration tests PASS, khong skip.
- Tenant A login khong doc hoac ghi duoc tenant B, ngay ca khi set `cs.actor_id`.
- Login A khong `SET ROLE` sang B va khong sua mapping role-owner.
- Shared runtime cu khong co quyen truy cap schema isolation prototype.
- Tat ca Python / Docker / RLS jobs khac PASS.

## 5. Ket qua va buoc tiep theo

Sau Step 41, ta moi co *proof of design*, KHONG phai tenant isolation da duoc sua trong app.
Step 42 la tich hop identity binding, provisioning/rotation secrets va migration
staging theo ke hoach cu the sau khi kiem chung compatibility va recovery.
Beta van NO-GO va localhost demo van giu nguyen.
