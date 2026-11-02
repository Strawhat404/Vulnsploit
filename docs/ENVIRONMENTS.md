# Environments and branches

| Branch    | Environment | Deployed from        | Purpose                                   |
|-----------|-------------|----------------------|-------------------------------------------|
| `main`    | Production  | `render.yaml`        | Real users. Only receives tested changes. |
| `develop` | Staging     | `render.staging.yaml`| Integration and testing before production.|

## Workflow

```
feature branch ──PR──▶ develop ──(auto-deploys to staging, test it)──PR──▶ main ──(production)
```

1. Branch off `develop` (`feature/...`, `fix/...`, `chore/...`) and open a PR **into `develop`**.
2. CI (`Backend tests`) must pass. Merging deploys to staging.
3. Test on staging. When happy, open a PR **`develop` → `main`**. Merging deploys to production.
4. Never push straight to `main` or `develop`.

## Staging setup (one time)

Staging is a fully separate stack: own database, Redis, secret key and URLs. It must
never share any of them with production.

1. Render dashboard: **New + → Blueprint**, pick this repo, branch **`develop`**,
   Blueprint file **`render.staging.yaml`**.
2. Render prompts once for the `sync: false` values:
   - `CORS_ALLOWED_ORIGINS` and `SITE_URL`: the **staging frontend** URL.
   - `GEMINI_API_KEY`: leave **empty**. Staging then uses the rule-based fallback and
     never sends test data to Gemini.
3. Deploy the staging frontend (see the frontend repo's `docs/ENVIRONMENTS.md`) with
   `VITE_API_URL` set to the staging API URL.
4. Staging email uses the console backend, so messages appear in the service log and
   nothing is sent to real people.

Staging runs four resources (API, Beat, Redis, Postgres), so it costs about as much as production.

## Things to know

- **Celery Beat.** Beat fires scheduled scans and the daily verification-expiry warning.
  Exactly one Beat process may run per environment. Staging has its own `vulnsploit-staging-beat`
  service. **`render.yaml` (production) does not run Beat**, so scheduled scans and expiry
  warnings do not fire in production until a Beat service is added there too.
- **Production branch is pinned.** `render.yaml` sets `branch: main` explicitly so a change of
  the GitHub default branch can never repoint production.
- **Verification.** All targets must be verified before scanning (`REQUIRE_TARGET_VERIFICATION`).
  A staging database starts empty, so verify targets there too.
- **Never** set `ALLOW_PRIVATE_TARGETS=True` on a shared or hosted environment.

## CI

`.github/workflows/backend-tests.yml` runs on every PR and on pushes to `develop`/`main`:
Django system check, migrations-in-sync check, then the pytest suite (Python 3.11, same as
the Dockerfile). Run the same locally:

```bash
cd backend
python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
SECRET_KEY=x DEBUG=True .venv/bin/python manage.py check
.venv/bin/python -m pytest
```
