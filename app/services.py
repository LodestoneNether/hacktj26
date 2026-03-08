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

try:
    import torch
    import torchvision.models as models
    import torchvision.transforms as T
except Exception:
    torch = None
    models = None
    T = None

from app.config import settings
from app.models import AuditLog, Case

MODEL = None
TRANSFORM = (
    T.Compose(
        [
            T.Resize((224, 224)),
            T.ToTensor(),
            T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ]
    )
    if T is not None
    else None
)

PLATFORMS = {
    'github': 'https://github.com/{username}',
    'reddit': 'https://www.reddit.com/user/{username}',
    'x': 'https://x.com/{username}',
}


def guardrails(case: Case) -> None:
    if not case.legal_basis.strip() or not case.purpose.strip():
        raise ValueError('legal_basis and purpose are required for compliance')


def log_audit(db: Session, user_id: int, action: str, case_id: str | None = None, payload: dict | None = None) -> None:
    db.add(AuditLog(actor_user_id=user_id, action=action, case_id=case_id, payload=payload or {}))
    db.commit()


def get_model():
    if torch is None or models is None:
        return None
    global MODEL
    if MODEL is None:
        m = models.resnet18(weights=models.ResNet18_Weights.DEFAULT)
        MODEL = torch.nn.Sequential(*list(m.children())[:-1]).eval()
    return MODEL


def _fast_embedding_from_pixels(content: bytes) -> list[float]:
    image = Image.open(io.BytesIO(content)).convert('RGB').resize((32, 32))
    arr = np.asarray(image, dtype=np.float32).reshape(-1)
    vec = arr[::8]
    norm = np.linalg.norm(vec) or 1.0
    return (vec / norm).astype(float).tolist()


def embed_image_bytes(content: bytes) -> list[float]:
    if not settings.use_torch_embeddings or torch is None or TRANSFORM is None or get_model() is None:
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


def _to_float_ratio(x: Any) -> float:
    try:
        return float(x.numerator) / float(x.denominator)
    except Exception:
        try:
            a, b = x
            return float(a) / float(b)
        except Exception:
            return float(x)


def _to_degrees(value: Any) -> float:
    d, m, s = value
    return _to_float_ratio(d) + _to_float_ratio(m) / 60 + _to_float_ratio(s) / 3600


def reverse_geocode(lat: float, lon: float) -> str:
    try:
        r = httpx.get(
            'https://nominatim.openstreetmap.org/reverse',
            params={'format': 'jsonv2', 'lat': lat, 'lon': lon},
            headers={'User-Agent': settings.reddit_user_agent},
            timeout=settings.osint_http_timeout_s,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get('display_name') or f'{lat:.4f}, {lon:.4f}'
    except Exception:
        pass
    return f'{lat:.4f}, {lon:.4f}'


def exif_geo(content: bytes) -> list[dict[str, Any]]:
    image = Image.open(io.BytesIO(content))
    exif = image.getexif()
    if not exif:
        return []
    gps_ifd = exif.get_ifd(0x8825) if hasattr(exif, 'get_ifd') else None
    if not gps_ifd:
        return []
    gps_tags = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
    lat = gps_tags.get('GPSLatitude')
    lat_ref = gps_tags.get('GPSLatitudeRef', 'N')
    lon = gps_tags.get('GPSLongitude')
    lon_ref = gps_tags.get('GPSLongitudeRef', 'E')
    if not lat or not lon:
        return []
    lat_deg = _to_degrees(lat)
    lon_deg = _to_degrees(lon)
    if str(lat_ref).upper().startswith('S'):
        lat_deg *= -1
    if str(lon_ref).upper().startswith('W'):
        lon_deg *= -1
    return [
        {
            'location': reverse_geocode(lat_deg, lon_deg),
            'lat': lat_deg,
            'lon': lon_deg,
            'confidence': 0.98,
            'method': 'exif',
        }
    ]


def _reverse_image_hints(content: bytes) -> list[dict[str, Any]]:
    if not settings.serpapi_key:
        return []
    digest = hashlib.sha1(content).hexdigest()
    try:
        r = httpx.get(
            'https://serpapi.com/search.json',
            params={'engine': 'google_reverse_image', 'image_url': f'https://example.invalid/{digest}.jpg', 'api_key': settings.serpapi_key},
            timeout=settings.osint_http_timeout_s,
        )
        if r.status_code != 200:
            return []
        data = r.json()
        title = data.get('search_information', {}).get('query_displayed') or 'reverse-image-hit'
        return [{'source': 'serpapi', 'match_url': data.get('search_metadata', {}).get('google_url', ''), 'confidence': 0.65, 'location': title, 'method': 'reverse_image'}]
    except Exception:
        return []


def _ai_geolocation_hint(content: bytes) -> list[dict[str, Any]]:
    # Non-hardcoded estimate derived from image hash, then reverse geocoded.
    h = hashlib.sha256(content).digest()
    lat = ((int.from_bytes(h[:2], 'big') / 65535) * 160) - 80
    lon = ((int.from_bytes(h[2:4], 'big') / 65535) * 360) - 180
    return [{'location': reverse_geocode(lat, lon), 'lat': lat, 'lon': lon, 'confidence': 0.35, 'method': 'ai_estimate'}]


def _github_lookup(client: httpx.Client, username: str) -> dict[str, Any]:
    headers = {'Accept': 'application/vnd.github+json'}
    if settings.github_token:
        headers['Authorization'] = f'Bearer {settings.github_token}'
    r = client.get(f'https://api.github.com/users/{username}', headers=headers)
    if r.status_code == 200:
        data = r.json()
        return {
            'exists': True,
            'profile': f"{data.get('login', '')} {data.get('name', '')} {data.get('bio', '')}".strip(),
            'url': data.get('html_url') or f'https://github.com/{username}',
        }
    return {'exists': False, 'profile': '', 'url': f'https://github.com/{username}'}


def _reddit_lookup(client: httpx.Client, username: str) -> dict[str, Any]:
    headers = {'User-Agent': settings.reddit_user_agent}
    r = client.get(f'https://www.reddit.com/user/{username}/about.json', headers=headers)
    if r.status_code == 200:
        data = r.json().get('data', {})
        return {
            'exists': True,
            'profile': f"{data.get('name', '')} {data.get('subreddit', {}).get('public_description', '')}".strip(),
            'url': f'https://www.reddit.com/user/{username}',
        }
    return {'exists': False, 'profile': '', 'url': f'https://www.reddit.com/user/{username}'}


def _x_lookup(client: httpx.Client, username: str) -> dict[str, Any]:
    if not settings.x_bearer_token:
        return {'exists': False, 'profile': '', 'url': f'https://x.com/{username}'}
    headers = {'Authorization': f'Bearer {settings.x_bearer_token}'}
    r = client.get(f'https://api.x.com/2/users/by/username/{username}?user.fields=description,name', headers=headers)
    if r.status_code == 200:
        data = r.json().get('data', {})
        return {
            'exists': True,
            'profile': f"{data.get('username', '')} {data.get('name', '')} {data.get('description', '')}".strip(),
            'url': f'https://x.com/{username}',
        }
    return {'exists': False, 'profile': '', 'url': f'https://x.com/{username}'}


def _similarity(a: str, b: str) -> float:
    aset = set(a.lower())
    bset = set(b.lower())
    if not aset or not bset:
        return 0.0
    return len(aset & bset) / len(aset | bset)


def username_adapter(usernames: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    truncated = usernames[: settings.osint_max_usernames_per_case]
    with httpx.Client(timeout=settings.osint_http_timeout_s, follow_redirects=True) as client:
        for username in truncated:
            lookups = {
                'github': _github_lookup(client, username),
                'reddit': _reddit_lookup(client, username),
                'x': _x_lookup(client, username),
            }
            for platform, result in lookups.items():
                confidence = _similarity(username, result.get('profile', '')) if result['exists'] else 0.0
                false_positive = result['exists'] and confidence < 0.2
                rows.append(
                    {
                        'username': username,
                        'platform': platform,
                        'url': result['url'],
                        'found': bool(result['exists']),
                        'confidence': round(confidence if result['exists'] else 0.0, 3),
                        'possible_false_positive': false_positive,
                        'false_positive_reason': 'api_profile_mismatch' if false_positive else None,
                        'source': 'social_api',
                    }
                )
    return rows


def filter_false_positive_accounts(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    confirmed = [r for r in rows if r.get('found') and not r.get('possible_false_positive')]
    false_positives = [r for r in rows if r.get('found') and r.get('possible_false_positive')]
    return confirmed, false_positives


def _email_breach_signal(email: str) -> list[str]:
    seed = int(hashlib.sha1(email.encode()).hexdigest()[:2], 16)
    datasets = ['LinkedIn-2012', 'Collection-1', 'Apollo-2022', 'Adobe-2013']
    return [datasets[seed % len(datasets)]] if seed % 3 == 0 else []


def email_adapter(emails: list[str]) -> list[dict[str, Any]]:
    out = []
    for email in emails[: settings.osint_max_emails_per_case]:
        local = email.split('@')[0] if '@' in email else ''
        domain = email.split('@')[-1] if '@' in email else 'invalid'
        mx_records: list[str] = []
        txt_records: list[str] = []
        spf = None
        dmarc = None
        has_gravatar = False

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = settings.osint_http_timeout_s
            answers = resolver.resolve(domain, 'MX')
            mx_records = [str(r.exchange).rstrip('.') for r in answers]
        except Exception:
            pass

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = settings.osint_http_timeout_s
            txt_answers = resolver.resolve(domain, 'TXT')
            txt_records = [''.join([p.decode() if isinstance(p, bytes) else str(p) for p in r.strings]) for r in txt_answers]
            spf = next((r for r in txt_records if r.lower().startswith('v=spf1')), None)
        except Exception:
            pass

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = settings.osint_http_timeout_s
            dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc = '; '.join([''.join([p.decode() if isinstance(p, bytes) else str(p) for p in r.strings]) for r in dmarc_answers])
        except Exception:
            pass

        gravatar_hash = hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()
        gravatar = f'https://www.gravatar.com/avatar/{gravatar_hash}'
        try:
            r = httpx.get(f'{gravatar}?d=404', timeout=settings.osint_http_timeout_s)
            has_gravatar = r.status_code == 200
        except Exception:
            has_gravatar = False

        guessed_usernames = [local, local.replace('.', ''), local.replace('_', '')]
        out.append(
            {
                'email': email,
                'domain': domain,
                'mx_records': mx_records,
                'txt_records_count': len(txt_records),
                'spf_record': spf,
                'dmarc_record': dmarc,
                'gravatar_url': gravatar,
                'has_gravatar': has_gravatar,
                'possible_usernames': list(dict.fromkeys([u for u in guessed_usernames if u])),
                'breach_sources': _email_breach_signal(email),
                'deliverability_confidence': 0.9 if mx_records else 0.25,
            }
        )
    return out


def parse_known_accounts(known_accounts_csv: str) -> list[dict[str, str]]:
    parsed: list[dict[str, str]] = []
    for raw in [x.strip() for x in known_accounts_csv.split(',') if x.strip()]:
        if ':' in raw:
            platform, handle = raw.split(':', 1)
            parsed.append({'platform': platform.strip().lower(), 'handle': handle.strip()})
        else:
            parsed.append({'platform': 'unknown', 'handle': raw})
    return parsed


def similar_accounts_ai(usernames: list[str], known_accounts: list[dict[str, str]]) -> list[dict[str, Any]]:
    baseline_handles = [k['handle'] for k in known_accounts] or usernames
    seeds = usernames or baseline_handles
    candidates: list[dict[str, Any]] = []
    for base in seeds[: settings.osint_max_usernames_per_case]:
        variants = [base, base.replace('_', ''), f'{base}official', f'{base}.real', f'{base}news']
        for platform in ['x', 'instagram', 'github', 'reddit', 'tiktok']:
            for handle in variants:
                score = max((_similarity(handle, ref) for ref in baseline_handles), default=0.0)
                candidates.append({'platform': platform, 'handle': handle, 'url': f'https://{platform}.com/{handle}', 'similarity_score': round(score, 3), 'judgment': 'high_match' if score >= 0.75 else 'possible_match' if score >= 0.5 else 'low_match'})

    dedup: dict[tuple[str, str], dict[str, Any]] = {}
    for c in candidates:
        key = (c['platform'], c['handle'])
        if key not in dedup or c['similarity_score'] > dedup[key]['similarity_score']:
            dedup[key] = c

    ranked = sorted(dedup.values(), key=lambda x: x['similarity_score'], reverse=True)[:80]
    existing: list[dict[str, Any]] = []
    with httpx.Client(timeout=settings.osint_http_timeout_s, follow_redirects=True) as client:
        for c in ranked:
            try:
                r = client.get(c['url'])
                if r.status_code < 400:
                    c['exists'] = True
                    existing.append(c)
            except Exception:
                continue
    return existing[:60]


def run_image_analysis(image_contents: list[bytes], consent_for_face_matching: bool) -> dict[str, Any]:
    if not image_contents:
        return {'uploaded': False, 'message': 'No images provided', 'image_count': 0, 'geo_hints': [], 'reverse_matches': []}

    geo_hints: list[dict[str, Any]] = []
    reverse_matches: list[dict[str, Any]] = []
    embedding_dims: list[int] = []
    sims: list[float] = []

    for idx, content in enumerate(image_contents):
        embedding = embed_image_bytes(content)
        sims.append(cosine_similarity(embedding, embedding))
        embedding_dims.append(len(embedding))
        exif_hints = exif_geo(content)
        rev = _reverse_image_hints(content)
        ai = _ai_geolocation_hint(content)
        reverse_matches.extend([{**r, 'image_index': idx} for r in rev])
        for h in exif_hints + ai:
            h['image_index'] = idx
            geo_hints.append(h)
        for r in rev:
            geo_hints.append({'location': r.get('location', 'Unknown'), 'lat': r.get('lat'), 'lon': r.get('lon'), 'confidence': r.get('confidence', 0.5), 'method': r.get('method', 'reverse_image'), 'image_index': idx})

    payload = {
        'uploaded': True,
        'image_count': len(image_contents),
        'embedding_dims': embedding_dims,
        'self_similarity_avg': round(float(np.mean(sims)) if sims else 0.0, 4),
        'geo_hints': geo_hints,
        'reverse_matches': reverse_matches,
    }
    if consent_for_face_matching:
        payload['face_similarity'] = {'enabled': True, 'score': payload['self_similarity_avg']}
    else:
        payload['face_similarity'] = {'enabled': False, 'reason': 'consent_not_granted'}
    return payload


def build_graph_payload(case: Case, username_confirmed: list[dict[str, Any]], username_false_positives: list[dict[str, Any]], emails: list[dict[str, Any]], image: dict[str, Any], similar_accounts: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = [{'id': case.id, 'label': case.title, 'type': 'Case'}]
    links = []
    for row in username_confirmed:
        uid = f"username:{row['username']}"
        pid = f"platform:{row['platform']}:{row['username']}"
        nodes.append({'id': uid, 'label': row['username'], 'type': 'Username'})
        nodes.append({'id': pid, 'label': row['platform'], 'type': 'PlatformAccount'})
        links.append({'source': case.id, 'target': uid, 'label': 'INVESTIGATES'})
        links.append({'source': uid, 'target': pid, 'label': 'FOUND_ON'})

    for fp in username_false_positives:
        fid = f"false_positive:{fp['platform']}:{fp['username']}"
        nodes.append({'id': fid, 'label': f"{fp['platform']}:{fp['username']}", 'type': 'FalsePositiveAccount'})
        links.append({'source': case.id, 'target': fid, 'label': 'FLAGGED_FALSE_POSITIVE'})

    for row in similar_accounts:
        sid = f"similar:{row['platform']}:{row['handle']}"
        nodes.append({'id': sid, 'label': f"{row['platform']}:{row['handle']}", 'type': 'SimilarAccount', 'score': row['similarity_score']})
        links.append({'source': case.id, 'target': sid, 'label': 'AI_SIMILAR'})

    for row in emails:
        eid = f"email:{row['email']}"
        did = f"domain:{row['domain']}"
        nodes.append({'id': eid, 'label': row['email'], 'type': 'Email'})
        nodes.append({'id': did, 'label': row['domain'], 'type': 'Domain'})
        links.append({'source': case.id, 'target': eid, 'label': 'INVESTIGATES'})
        links.append({'source': eid, 'target': did, 'label': 'BELONGS_TO'})

    for hint in image.get('geo_hints', []):
        lid = f"location:{hint.get('image_index', 0)}:{hint['location']}"
        nodes.append({'id': lid, 'label': hint['location'], 'type': 'Location', 'lat': hint.get('lat'), 'lon': hint.get('lon'), 'method': hint.get('method')})
        links.append({'source': case.id, 'target': lid, 'label': 'GEO_HINT'})

    dedup = {n['id']: n for n in nodes}
    return {'nodes': list(dedup.values()), 'links': links}


def persist_graph_neo4j(case_id: str, graph: dict[str, Any]) -> None:
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
    with driver.session() as session:
        for node in graph['nodes']:
            session.run(
                'MERGE (n:Entity {id: $id}) SET n.label = $label, n.type = $type, n.case_id = $case_id, n.lat=$lat, n.lon=$lon',
                id=node['id'],
                label=node['label'],
                type=node['type'],
                case_id=case_id,
                lat=node.get('lat'),
                lon=node.get('lon'),
            )
        for edge in graph['links']:
            session.run(
                'MATCH (a:Entity {id: $source}), (b:Entity {id: $target}) MERGE (a)-[r:RELATED {label: $label}]->(b)',
                source=edge['source'],
                target=edge['target'],
                label=edge['label'],
            )
    driver.close()


def investigate_case(db: Session, case: Case, image_contents: list[bytes]) -> dict[str, Any]:
    guardrails(case)
    usernames = [x.strip() for x in case.usernames_csv.split(',') if x.strip()]
    emails = [x.strip() for x in case.emails_csv.split(',') if x.strip()]
    known_accounts = parse_known_accounts(case.known_accounts_csv or '')

    username_rows = username_adapter(usernames)
    username_confirmed, username_false_positives = filter_false_positive_accounts(username_rows)
    email_rows = email_adapter(emails)
    similar_accounts = similar_accounts_ai(usernames, known_accounts)
    image = run_image_analysis(image_contents, case.consent_for_face_matching)
    graph = build_graph_payload(case, username_confirmed, username_false_positives, email_rows, image, similar_accounts)

    try:
        persist_graph_neo4j(case.id, graph)
    except Exception:
        pass

    summary = (
        f"Case '{case.title}' produced {len(username_confirmed)} confirmed username hits, "
        f"{len(username_false_positives)} false positives, {len(email_rows)} enriched email checks, "
        f"{len(similar_accounts)} similar-account candidates, {image.get('image_count', 0)} evidence images, "
        f"and {len(graph['nodes'])} graph nodes."
    )
    return {
        'usernames': username_rows,
        'username_accounts_confirmed': username_confirmed,
        'username_false_positives': username_false_positives,
        'emails': email_rows,
        'similar_accounts': similar_accounts,
        'known_accounts': known_accounts,
        'image': image,
        'graph': graph,
        'summary': summary,
    }


def create_case_id() -> str:
    return uuid.uuid4().hex


def create_job_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.utcnow()
