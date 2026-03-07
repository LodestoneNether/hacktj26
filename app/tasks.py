from datetime import datetime

from app.celery_app import celery
from app.db import SessionLocal
from app.models import Case, Job
from app.services import investigate_case


@celery.task(name='jobs.investigate_case')
def investigate_case_task(job_id: str, case_id: str, image_content: bytes | None = None) -> None:
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        case = db.query(Case).filter(Case.id == case_id).first()
        if not job or not case:
            return
        findings = investigate_case(db, case, image_content)
        job.findings = {
            'usernames': findings['usernames'],
            'emails': findings['emails'],
            'similar_accounts': findings['similar_accounts'],
            'known_accounts': findings['known_accounts'],
            'image': findings['image'],
            'graph': findings['graph'],
        }
        job.summary = findings['summary']
        job.status = 'completed'
        job.completed_at = datetime.utcnow()
        db.commit()
    except Exception:
        if job:
            job.status = 'failed'
            db.commit()
        raise
    finally:
        db.close()
