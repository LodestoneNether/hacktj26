import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import time

from fastapi.testclient import TestClient

from app.main import app, CASES, JOBS


client = TestClient(app)


def setup_function() -> None:
    CASES.clear()
    JOBS.clear()


def test_case_creation_and_listing() -> None:
    response = client.post(
        "/api/cases",
        data={
            "title": "Missing person lead",
            "notes": "Check username trail",
            "usernames": "alice,bob",
            "emails": "alice@example.com",
        },
    )
    assert response.status_code == 200
    case_id = response.json()["case_id"]

    listing = client.get("/api/cases")
    assert listing.status_code == 200
    data = listing.json()
    assert len(data) == 1
    assert data[0]["id"] == case_id


def test_investigation_job_completes() -> None:
    create = client.post(
        "/api/cases",
        data={
            "title": "Cyber check",
            "notes": "Investigate",
            "usernames": "analyst1",
            "emails": "analyst1@company.com",
        },
    )
    case_id = create.json()["case_id"]

    job = client.post(f"/api/cases/{case_id}/investigate")
    assert job.status_code == 200
    job_id = job.json()["job_id"]

    deadline = time.time() + 5
    status = None
    while time.time() < deadline:
        current = client.get(f"/api/jobs/{job_id}")
        assert current.status_code == 200
        payload = current.json()
        status = payload["status"]
        if status == "completed":
            assert payload["findings"]["graph"]["nodes"]
            break
        time.sleep(0.2)

    assert status == "completed"

    summary = client.get(f"/api/cases/{case_id}/summary")
    assert summary.status_code == 200
    assert "Top next step" in summary.json()["summary"]
