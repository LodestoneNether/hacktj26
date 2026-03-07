from __future__ import annotations

import hashlib
import io
import uuid
from datetime import datetime
from typing import Any

import dns.resolver
import httpx
import numpy as np
from neo4j import GraphDatabase
from PIL import Image, ExifTags
from sqlalchemy.orm import Session
import torch
import torchvision.models as models
import torchvision.transforms as T

from app.config import settings
from app.models import AuditLog, Case

MODEL = None
TRANSFORM = T.Compose([
    T.Resize((224, 224)),
    T.ToTensor(),
    T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])

PLATFORMS = {
    'github': 'https://github.com/{username}',
    'reddit': 'https://www.reddit.com/user/{username}',
    'instagram': 'https://www.instagram.com/{username}/',
    'medium': 'https://medium.com/@{username}',
}


def guardrails(case: Case) -> None:
    if not case.legal_basis.strip() or not case.purpose.strip():
        raise ValueError('legal_basis and purpose are required for compliance')


def log_audit(db: Session, user_id: int, action: str, case_id: str | None = None, payload: dict | None = None) -> None:
    db.add(AuditLog(actor_user_id=user_id, action=action, case_id=case_id, payload=payload or {}))
    db.commit()


def get_model() -> torch.nn.Module:
    global MODEL
    if MODEL is None:
        m = models.resnet18(weights=models.ResNet18_Weights.DEFAULT)
        MODEL = torch.nn.Sequential(*list(m.children())[:-1]).eval()
    return MODEL


def _fast_embedding_from_pixels(content: bytes) -> list[float]:
    image = Image.open(io.BytesIO(content)).convert('RGB').resize((32, 32))
    arr = np.asarray(image, dtype=np.float32).reshape(-1)
    # deterministic, light embedding for fast local runs
    vec = arr[::8]
    norm = np.linalg.norm(vec) or 1.0
    return (vec / norm).astype(float).tolist()


def embed_image_bytes(content: bytes) -> list[float]:
    if not settings.use_torch_embeddings:
        return _fast_embedding_from_pixels(content)

    image = Image.open(io.BytesIO(content)).convert('RGB')
    tensor = TRANSFORM(image).unsqueeze(0)
    with torch.no_grad():
        emb = get_model()(tensor).flatten().numpy()
    norm = np.linalg.norm(emb) or 1.0
    return (emb / norm).astype(float).tolist()


def cosine_similarity(v1: list[float], v2: list[float]) -> float:
    a = np.array(v1)
    b = np.array(v2)
    denom = (np.linalg.norm(a) * np.linalg.norm(b)) or 1.0
    return float(np.dot(a, b) / denom)


def exif_geo(content: bytes) -> list[dict[str, Any]]:
    image = Image.open(io.BytesIO(content))
    exif = image.getexif()
    if not exif:
        return []
    tags = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.items()}
    gps = tags.get('GPSInfo')
    if gps:
        return [{'location': 'GPS metadata present', 'confidence': 0.9}]
    return []


def username_adapter(usernames: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    truncated = usernames[: settings.osint_max_usernames_per_case]
    with httpx.Client(timeout=settings.osint_http_timeout_s, follow_redirects=True) as client:
        for username in truncated:
            for platform, template in PLATFORMS.items():
                url = template.format(username=username)
                try:
                    r = client.get(url)
                    found = r.status_code < 400
                    confidence = 0.9 if found else 0.1
                except Exception:
                    found = False
                    confidence = 0.0
                rows.append({'username': username, 'platform': platform, 'url': url, 'found': found, 'confidence': confidence})
    return rows


def email_adapter(emails: list[str]) -> list[dict[str, Any]]:
    out = []
    for email in emails[: settings.osint_max_emails_per_case]:
        domain = email.split('@')[-1] if '@' in email else 'invalid'
        mx_records = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = settings.osint_http_timeout_s
            answers = resolver.resolve(domain, 'MX')
            mx_records = [str(r.exchange).rstrip('.') for r in answers]
        except Exception:
            pass
        gravatar = 'https://www.gravatar.com/avatar/' + hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()
        out.append({
            'email': email,
            'domain': domain,
            'mx_records': mx_records,
            'gravatar_url': gravatar,
            'deliverability_confidence': 0.85 if mx_records else 0.25,
        })
    return out


def run_image_analysis(image_content: bytes | None, consent_for_face_matching: bool) -> dict[str, Any]:
    if not image_content:
        return {'uploaded': False, 'message': 'No image provided'}
    embedding = embed_image_bytes(image_content)
    sim = cosine_similarity(embedding, embedding)
    geo = exif_geo(image_content)
    payload = {
        'uploaded': True,
        'embedding_dim': len(embedding),
        'self_similarity': sim,
        'geo_hints': geo,
        'reverse_matches': [],
    }
    if consent_for_face_matching:
        payload['face_similarity'] = {'enabled': True, 'score': round(sim, 4)}
    else:
        payload['face_similarity'] = {'enabled': False, 'reason': 'consent_not_granted'}
    return payload


def build_graph_payload(case: Case, usernames: list[dict[str, Any]], emails: list[dict[str, Any]], image: dict[str, Any]) -> dict[str, Any]:
    nodes = [{'id': case.id, 'label': case.title, 'type': 'Case'}]
    links = []
    for row in usernames:
        uid = f"username:{row['username']}"
        nodes.append({'id': uid, 'label': row['username'], 'type': 'Username'})
        if row['found']:
            pid = f"platform:{row['platform']}:{row['username']}"
            nodes.append({'id': pid, 'label': row['platform'], 'type': 'PlatformAccount'})
            links.append({'source': uid, 'target': pid, 'label': 'FOUND_ON'})
    for row in emails:
        eid = f"email:{row['email']}"
        did = f"domain:{row['domain']}"
        nodes.append({'id': eid, 'label': row['email'], 'type': 'Email'})
        nodes.append({'id': did, 'label': row['domain'], 'type': 'Domain'})
        links.append({'source': eid, 'target': did, 'label': 'BELONGS_TO'})
    for hint in image.get('geo_hints', []):
        lid = f"location:{hint['location']}"
        nodes.append({'id': lid, 'label': hint['location'], 'type': 'Location'})
        links.append({'source': case.id, 'target': lid, 'label': 'GEO_HINT'})
    dedup = {n['id']: n for n in nodes}
    return {'nodes': list(dedup.values()), 'links': links}


def persist_graph_neo4j(case_id: str, graph: dict[str, Any]) -> None:
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
    with driver.session() as session:
        for node in graph['nodes']:
            session.run(
                'MERGE (n:Entity {id: $id}) SET n.label = $label, n.type = $type, n.case_id = $case_id',
                id=node['id'], label=node['label'], type=node['type'], case_id=case_id,
            )
        for edge in graph['links']:
            session.run(
                'MATCH (a:Entity {id: $source}), (b:Entity {id: $target}) '
                'MERGE (a)-[r:RELATED {label: $label}]->(b)',
                source=edge['source'], target=edge['target'], label=edge['label'],
            )
    driver.close()


def investigate_case(db: Session, case: Case, image_content: bytes | None) -> dict[str, Any]:
    guardrails(case)
    usernames = [x.strip() for x in case.usernames_csv.split(',') if x.strip()]
    emails = [x.strip() for x in case.emails_csv.split(',') if x.strip()]
    username_rows = username_adapter(usernames)
    email_rows = email_adapter(emails)
    image = run_image_analysis(image_content, case.consent_for_face_matching)
    graph = build_graph_payload(case, username_rows, email_rows, image)
    try:
        persist_graph_neo4j(case.id, graph)
    except Exception:
        pass
    summary = (
        f"Case '{case.title}' produced {len(username_rows)} username checks, "
        f"{len(email_rows)} email checks, and {len(graph['nodes'])} graph nodes."
    )
    return {'usernames': username_rows, 'emails': email_rows, 'image': image, 'graph': graph, 'summary': summary}


def create_case_id() -> str:
    return uuid.uuid4().hex


def create_job_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.utcnow()
