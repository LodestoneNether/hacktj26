from __future__ import annotations

import base64

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import create_access_token, get_password_hash, require_roles, verify_password
from app.db import Base, SessionLocal, active_database_url, engine, get_db
from app.models import Case, Job, Role, User
from app.services import create_case_id, create_job_id, log_audit, utcnow
from app.tasks import investigate_case_task

app = FastAPI(title='OSINT AI Investigator - Productionized Web')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.mount('/static', StaticFiles(directory='app/static'), name='static')
templates = Jinja2Templates(directory='app/templates')


@app.on_event('startup')
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == 'admin@local').first()
        if not admin:
            db.add(User(email='admin@local', hashed_password=get_password_hash('admin123'), role=Role.admin))
            db.commit()
        print(f'Active database URL: {active_database_url}')
    finally:
        db.close()


@app.get('/', response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    return templates.TemplateResponse('index.html', {'request': request, 'cases': cases})


@app.get('/cases/{case_id}', response_class=HTMLResponse)
def case_page(request: Request, case_id: str, db: Session = Depends(get_db)) -> HTMLResponse:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail='Case not found')
    job = db.query(Job).filter(Job.case_id == case_id).order_by(Job.created_at.desc()).first()
    return templates.TemplateResponse('case.html', {'request': request, 'case': case, 'job': job})


@app.post('/api/auth/token')
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    return {'access_token': create_access_token(user.email), 'token_type': 'bearer'}


@app.post('/api/cases')
def create_case(
    title: str = Form(...),
    notes: str = Form(''),
    usernames: str = Form(''),
    emails: str = Form(''),
    legal_basis: str = Form(...),
    purpose: str = Form(...),
    consent_for_face_matching: bool = Form(False),
    image: UploadFile | None = File(None),
    user: User = Depends(require_roles(Role.admin, Role.investigator)),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    cid = create_case_id()
    case = Case(
        id=cid,
        title=title,
        notes=notes,
        legal_basis=legal_basis,
        purpose=purpose,
        consent_for_face_matching=consent_for_face_matching,
        usernames_csv=usernames,
        emails_csv=emails,
        created_at=utcnow(),
        created_by=user.id,
    )
    db.add(case)
    db.commit()
    log_audit(db, user.id, 'case_created', case_id=cid, payload={'title': title})

    if image:
        content = awaitable_read(image)
        encoded = base64.b64encode(content).decode()
        log_audit(db, user.id, 'image_uploaded', case_id=cid, payload={'size': len(content)})
    else:
        encoded = ''

    return {'case_id': cid, 'image_b64': encoded}


def awaitable_read(file: UploadFile) -> bytes:
    return file.file.read()


@app.post('/api/cases/{case_id}/investigate')
def investigate_case_endpoint(
    case_id: str,
    image_b64: str = Form(''),
    user: User = Depends(require_roles(Role.admin, Role.investigator)),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail='Case not found')

    jid = create_job_id()
    job = Job(id=jid, case_id=case_id, status='running', created_at=utcnow())
    db.add(job)
    db.commit()

    payload = base64.b64decode(image_b64.encode()) if image_b64 else None
    investigate_case_task.delay(jid, case_id, payload)
    log_audit(db, user.id, 'investigation_started', case_id=case_id, payload={'job_id': jid})
    return {'job_id': jid}


@app.get('/api/cases')
def list_cases(user: User = Depends(require_roles(Role.admin, Role.investigator, Role.viewer)), db: Session = Depends(get_db)) -> list[dict]:
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    return [
        {
            'id': c.id,
            'title': c.title,
            'notes': c.notes,
            'created_at': c.created_at.isoformat(),
            'legal_basis': c.legal_basis,
            'purpose': c.purpose,
        }
        for c in cases
    ]


@app.get('/api/jobs/{job_id}')
def job_status(job_id: str, user: User = Depends(require_roles(Role.admin, Role.investigator, Role.viewer)), db: Session = Depends(get_db)) -> dict:
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    return {
        'id': job.id,
        'case_id': job.case_id,
        'status': job.status,
        'findings': job.findings,
        'summary': job.summary,
    }


@app.get('/api/cases/{case_id}/graph')
def case_graph(case_id: str, user: User = Depends(require_roles(Role.admin, Role.investigator, Role.viewer)), db: Session = Depends(get_db)) -> dict:
    job = db.query(Job).filter(Job.case_id == case_id, Job.status == 'completed').order_by(Job.completed_at.desc()).first()
    if not job:
        return {'nodes': [], 'links': []}
    return job.findings.get('graph', {'nodes': [], 'links': []})


@app.get('/api/cases/{case_id}/summary')
def case_summary(case_id: str, user: User = Depends(require_roles(Role.admin, Role.investigator, Role.viewer)), db: Session = Depends(get_db)) -> dict:
    job = db.query(Job).filter(Job.case_id == case_id, Job.status == 'completed').order_by(Job.completed_at.desc()).first()
    if not job:
        return {'summary': 'No completed investigation yet.'}
    return {'summary': job.summary}
