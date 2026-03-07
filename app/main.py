from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request


app = FastAPI(title="OSINT AI Investigator (Web MVP)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@dataclass
class InvestigationCase:
    id: str
    title: str
    notes: str
    created_at: str
    usernames: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    image_name: str | None = None


@dataclass
class Job:
    id: str
    case_id: str
    status: str
    created_at: str
    completed_at: str | None = None
    findings: dict[str, Any] = field(default_factory=dict)
    summary: str | None = None


CASES: dict[str, InvestigationCase] = {}
JOBS: dict[str, Job] = {}

PLATFORMS = [
    "github",
    "reddit",
    "x",
    "instagram",
    "tiktok",
    "medium",
    "youtube",
]


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def username_scan(usernames: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for username in usernames:
        seed = sum(ord(ch) for ch in username)
        for platform in PLATFORMS:
            confidence = round((((seed + len(platform) * 17) % 100) / 100), 2)
            found = confidence > 0.35
            if platform=='reddit':
                rows.append(
                    {
                        "username": username,
                        "platform": platform,
                        "found": found,
                        "confidence": confidence,
                        "url": f"https://{platform}.com/user/{username}" if found else None,
                    }
            elif platform in {'tiktok','medium','youtube'}:
                rows.append(
                    {
                        "username": username,
                        "platform": platform,
                        "found": found,
                        "confidence": confidence,
                        "url": f"https://{platform}.com/@{username}" if found else None,
                    }
            else:
                rows.append(
                    {
                        "username": username,
                        "platform": platform,
                        "found": found,
                        "confidence": confidence,
                        "url": f"https://{platform}.com/{username}" if found else None,
                    }
            )
    return rows


def email_scan(emails: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for email in emails:
        domain = email.split("@")[-1] if "@" in email else "unknown"
        rows.append(
            {
                "email": email,
                "domain": domain,
                "breach_risk": "high" if domain in {"yahoo.com", "hotmail.com"} else "low",
                "confidence": 0.62 if domain != "unknown" else 0.2,
            }
        )
    return rows


def image_analysis(image_name: str | None) -> dict[str, Any]:
    if not image_name:
        return {"uploaded": False, "message": "No image provided."}
    return {
        "uploaded": True,
        "image_name": image_name,
        "reverse_matches": [
            {"source": "news-cdn", "confidence": 0.71},
            {"source": "social-avatar", "confidence": 0.66},
        ],
        "geo_hints": [
            {"location": "Austin, TX", "confidence": 0.58},
            {"location": "San Marcos, TX", "confidence": 0.36},
        ],
    }


def build_graph(case: InvestigationCase, username_rows: list[dict[str, Any]], email_rows: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: list[dict[str, str]] = [{"id": case.id, "label": case.title, "type": "Case"}]
    links: list[dict[str, str]] = []

    for username in case.usernames:
        uid = f"username:{username}"
        nodes.append({"id": uid, "label": username, "type": "Username"})
        links.append({"source": case.id, "target": uid, "label": "INVESTIGATES"})

    for row in username_rows:
        if row["found"]:
            pid = f"platform:{row['platform']}:{row['username']}"
            nodes.append({"id": pid, "label": row["platform"], "type": "PlatformAccount"})
            links.append({"source": f"username:{row['username']}", "target": pid, "label": "FOUND_ON"})

    for email in case.emails:
        eid = f"email:{email}"
        nodes.append({"id": eid, "label": email, "type": "Email"})
        links.append({"source": case.id, "target": eid, "label": "INVESTIGATES"})

    for row in email_rows:
        did = f"domain:{row['domain']}"
        nodes.append({"id": did, "label": row["domain"], "type": "Domain"})
        links.append({"source": f"email:{row['email']}", "target": did, "label": "BELONGS_TO"})

    dedup = {n["id"]: n for n in nodes}
    return {"nodes": list(dedup.values()), "links": links}


def compose_summary(case: InvestigationCase, findings: dict[str, Any]) -> str:
    username_hits = sum(1 for row in findings["usernames"] if row["found"])
    email_count = len(findings["emails"])
    img_msg = "Image evidence included" if findings["image"]["uploaded"] else "No image evidence"
    return (
        f"Case '{case.title}' analyzed {len(case.usernames)} usernames and {email_count} emails. "
        f"Detected {username_hits} probable platform account hits. {img_msg}. "
        "Top next step: manually verify the highest-confidence platform matches and geo hints."
    )


def run_investigation(job_id: str) -> None:
    job = JOBS[job_id]
    case = CASES[job.case_id]
    import time
    time.sleep(0.2)
    username_rows = username_scan(case.usernames)
    time.sleep(0.2)
    email_rows = email_scan(case.emails)
    time.sleep(0.2)
    image_rows = image_analysis(case.image_name)
    graph = build_graph(case, username_rows, email_rows)
    findings = {
        "usernames": username_rows,
        "emails": email_rows,
        "image": image_rows,
        "graph": graph,
    }
    job.findings = findings
    job.summary = compose_summary(case, findings)
    job.status = "completed"
    job.completed_at = now_iso()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "cases": sorted(CASES.values(), key=lambda c: c.created_at, reverse=True),
        },
    )


@app.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_page(request: Request, case_id: str) -> HTMLResponse:
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    jobs = [job for job in JOBS.values() if job.case_id == case_id]
    latest_job = sorted(jobs, key=lambda j: j.created_at, reverse=True)[0] if jobs else None
    return templates.TemplateResponse(
        "case.html",
        {"request": request, "case": case, "job": latest_job},
    )


@app.post("/api/cases")
async def create_case(
    title: str = Form(...),
    notes: str = Form(""),
    usernames: str = Form(""),
    emails: str = Form(""),
    image: UploadFile | None = File(None),
) -> dict[str, str]:
    case_id = str(uuid.uuid4())
    case = InvestigationCase(
        id=case_id,
        title=title,
        notes=notes,
        created_at=now_iso(),
        usernames=[x.strip() for x in usernames.split(",") if x.strip()],
        emails=[x.strip() for x in emails.split(",") if x.strip()],
        image_name=image.filename if image else None,
    )
    CASES[case_id] = case
    return {"case_id": case_id}


@app.post("/api/cases/{case_id}/investigate")
async def investigate_case(case_id: str) -> dict[str, str]:
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    job_id = str(uuid.uuid4())
    JOBS[job_id] = Job(
        id=job_id,
        case_id=case_id,
        status="running",
        created_at=now_iso(),
    )
    threading.Thread(target=run_investigation, args=(job_id,), daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/cases")
async def list_cases() -> list[dict[str, Any]]:
    return [case.__dict__ for case in CASES.values()]


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.__dict__


@app.get("/api/cases/{case_id}/graph")
async def get_case_graph(case_id: str) -> dict[str, Any]:
    jobs = [job for job in JOBS.values() if job.case_id == case_id and job.status == "completed"]
    if not jobs:
        return {"nodes": [], "links": []}
    latest = sorted(jobs, key=lambda j: j.completed_at or "", reverse=True)[0]
    return latest.findings.get("graph", {"nodes": [], "links": []})


@app.get("/api/cases/{case_id}/summary")
async def get_case_summary(case_id: str) -> dict[str, str]:
    jobs = [job for job in JOBS.values() if job.case_id == case_id and job.status == "completed"]
    if not jobs:
        return {"summary": "No completed investigation yet."}
    latest = sorted(jobs, key=lambda j: j.completed_at or "", reverse=True)[0]
    return {"summary": latest.summary or ""}
