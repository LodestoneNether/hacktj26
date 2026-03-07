# OSINT AI Investigator — Web Platform (Productionized MVP)

This version implements the requested upgrades for the web stack:
- PostgreSQL-backed persistence
- Neo4j graph persistence
- Celery worker-based async execution
- Auth + RBAC + audit logging
- Real OSINT adapters with compliance guardrails
- Real image embeddings + face-similarity gating
- Map visualization of geo hints

## Implemented Architecture

- **API/Web:** FastAPI + Jinja templates + vanilla JS
- **Relational DB:** PostgreSQL via SQLAlchemy models (`users`, `cases`, `jobs`, `audit_logs`)

> If PostgreSQL is not reachable at startup, the app now automatically falls back to local SQLite (`sqlite:///./osint.db`) so `uvicorn app.main:app --reload` can still start for local development.
- **Graph DB:** Neo4j persistence for entity graph nodes/relationships
- **Workers:** Celery (`jobs.investigate_case`) with Redis broker/backend
- **Security:** OAuth2 password flow (JWT), role-based dependencies (`admin`, `investigator`, `viewer`)
- **Compliance:** Mandatory `legal_basis` + `purpose`; consent gate for face matching

## Feature Coverage

### 1) Username search adapters
Live HTTP-based checks against platform URL patterns (GitHub, Reddit, Instagram, Medium).

### 2) Email adapters
MX lookup (`dnspython`) + Gravatar hash artifact.

### 3) Image intelligence
- PyTorch `resnet18` embedding extraction
- Cosine similarity scoring
- EXIF GPS presence extraction
- Face-similarity output only when explicit consent is true

### 4) Graph construction + persistence
Graph payload built from usernames, emails, domains, and locations, then persisted into Neo4j.

### 5) Map visualization
Leaflet/OpenStreetMap map on case page, plotting geolocation hints.

## API Endpoints

- `POST /api/auth/token`
- `POST /api/cases`
- `GET /api/cases`
- `POST /api/cases/{id}/investigate`
- `GET /api/jobs/{job_id}`
- `GET /api/cases/{id}/graph`
- `GET /api/cases/{id}/summary`

## Local Setup

```bash
pip install -r requirements.txt
```

Set environment variables (example):

```bash
export DATABASE_URL='postgresql+psycopg2://postgres:postgres@localhost:5432/osint'
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USER='neo4j'
export NEO4J_PASSWORD='password'
export CELERY_BROKER_URL='redis://localhost:6379/0'
export CELERY_RESULT_BACKEND='redis://localhost:6379/1'
```

Run API:
```bash
uvicorn app.main:app --reload
```

Run worker:
```bash
celery -A app.celery_app.celery worker -l info
```

Default local admin:
- Email: `admin@local`
- Password: `admin123`

## Testing

Tests use sqlite + Celery eager mode via env overrides and monkeypatch external adapters.

```bash
pytest -q
```

## Investigation reliability/performance fixes

- Investigations now complete even if Celery broker/worker is down: API falls back to inline execution.
- Celery defaults to eager mode for local development (`CELERY_TASK_ALWAYS_EAGER=true`) to avoid jobs stuck in `running`.
- OSINT adapters now use tighter timeouts and per-case caps for usernames/emails.
- Torch embeddings are optional (`USE_TORCH_EMBEDDINGS=false` by default) to avoid long startup/download delays.
