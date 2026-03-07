# OSINT AI Investigator — Web Integration MVP

This repository now includes an implemented **web-focused MVP** based on the prior integration plan.

## What is implemented

### Web app experience
- Case dashboard (`/`) with a form for:
  - Case title + notes
  - Usernames (comma-separated)
  - Emails (comma-separated)
  - Optional image evidence upload
- Case detail page (`/cases/{id}`) with:
  - Run Investigation action
  - Live job status polling
  - AI-style summary panel
  - Evidence JSON panel
  - Graph snapshot JSON panel

### FastAPI backend (web API for frontend)
Implemented API endpoints:
- `POST /api/cases` — create case
- `GET /api/cases` — list cases
- `POST /api/cases/{id}/investigate` — start async investigation job
- `GET /api/jobs/{job_id}` — retrieve job status/findings
- `GET /api/cases/{id}/graph` — get graph projection
- `GET /api/cases/{id}/summary` — get generated summary

### Implemented investigation modules (web MVP versions)
- Username scan across a seeded set of platforms with confidence values
- Email scan with domain extraction + basic risk heuristic
- Image analysis placeholder with reverse-match and geolocation hints
- Graph builder that links case -> usernames/emails -> platform/domain entities
- Summary composer that generates concise investigative next-step guidance

## Architecture (web-only integration)
- **Frontend:** Server-rendered HTML templates + vanilla JS + CSS
- **Backend:** FastAPI
- **Async execution:** background worker thread per job
- **Data layer (MVP):** in-memory stores (`CASES`, `JOBS`)

> Note: Production pieces from the long-term plan (Neo4j, PostgreSQL, worker queues, auth/RBAC, LangChain/LLM orchestration, and PyTorch models) are intentionally scoped out of this MVP and can be layered in next.

## Local run

### 1) Install dependencies
```bash
pip install -r requirements.txt
```

### 2) Start server
```bash
uvicorn app.main:app --reload
```

### 3) Open app
Visit:
- `http://127.0.0.1:8000/`

## Project structure

```text
app/
  main.py              # FastAPI app + endpoints + async job pipeline
  templates/
    index.html         # dashboard/new-case page
    case.html          # case detail + run/status/results
  static/
    styles.css         # shared styling
    main.js            # dashboard form submission
    case.js            # run job + polling + result refresh
tests/
  test_app.py          # API and workflow tests
requirements.txt
README.md
```

## Next steps to align with full plan
1. Replace in-memory storage with PostgreSQL + Neo4j.
2. Move async tasks to Celery/RQ workers.
3. Add proper auth/RBAC and audit logging.
4. Integrate real OSINT adapters and compliance guardrails.
5. Add true image embeddings/face similarity and map visualization.
