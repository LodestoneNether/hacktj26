import os
import time
from pathlib import Path

os.environ['DATABASE_URL'] = 'sqlite:///./test.db'
os.environ['CELERY_TASK_ALWAYS_EAGER'] = 'true'
os.environ['CELERY_BROKER_URL'] = 'memory://'
os.environ['CELERY_RESULT_BACKEND'] = 'cache+memory://'
os.environ['SECRET_KEY'] = 'test-secret'

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.main import app
from app.db import Base, engine
from app import services


def setup_module() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_case_creation_and_investigation(monkeypatch) -> None:
    monkeypatch.setattr(services, 'username_adapter', lambda u: [{'username': 'alice', 'platform': 'github', 'url': 'x', 'found': True, 'confidence': 0.9}])
    monkeypatch.setattr(
        services,
        'email_adapter',
        lambda e: [
            {
                'email': 'alice@example.com',
                'domain': 'example.com',
                'mx_records': ['mx.example.com'],
                'txt_records_count': 2,
                'spf_record': 'v=spf1 include:_spf.example.com ~all',
                'dmarc_record': 'v=DMARC1; p=none',
                'gravatar_url': 'g',
                'has_gravatar': False,
                'possible_usernames': ['alice'],
                'breach_sources': [],
                'deliverability_confidence': 0.8,
            }
        ],
    )
    monkeypatch.setattr(
        services,
        'run_image_analysis',
        lambda c, consent: {
            'uploaded': bool(c),
            'reverse_matches': [],
            'geo_hints': [{'location': 'Austin, TX', 'lat': 30.2672, 'lon': -97.7431, 'confidence': 0.9, 'method': 'ai_cv'}],
        },
    )
    monkeypatch.setattr(
        services,
        'similar_accounts_ai',
        lambda usernames, known: [
            {'platform': 'instagram', 'handle': 'aliceofficial', 'url': 'u', 'similarity_score': 0.91, 'judgment': 'high_match', 'exists': True}
        ],
    )
    monkeypatch.setattr(services, 'persist_graph_neo4j', lambda case_id, graph: None)

    with TestClient(app) as client:
        response = client.post(
            '/api/auth/token',
            data={'username': 'admin@local', 'password': 'admin123'},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        assert response.status_code == 200
        headers = {'Authorization': f"Bearer {response.json()['access_token']}"}

        create = client.post(
            '/api/cases',
            data={
                'title': 'Missing person lead',
                'notes': 'investigate',
                'usernames': 'alice',
                'emails': 'alice@example.com',
                'known_accounts': 'instagram:aliceofficial',
                'legal_basis': 'public interest',
                'purpose': 'journalism',
                'consent_for_face_matching': 'true',
            },
            headers=headers,
        )
        assert create.status_code == 200
        case_id = create.json()['case_id']

        run = client.post(f'/api/cases/{case_id}/investigate', data={'images_b64_json': '[]'}, headers=headers)
        assert run.status_code == 200
        job_id = run.json()['job_id']

        deadline = time.time() + 5
        status = 'running'
        while time.time() < deadline:
            state = client.get(f'/api/jobs/{job_id}', headers=headers)
            assert state.status_code == 200
            payload = state.json()
            status = payload['status']
            if status == 'completed':
                assert payload['findings']['graph']['nodes']
                assert payload['findings']['similar_accounts']
                break
            time.sleep(0.2)

        assert status == 'completed'

        summary = client.get(f'/api/cases/{case_id}/summary', headers=headers)
        assert summary.status_code == 200
        assert 'similar-account candidates' in summary.json()['summary']


def test_multi_image_cache_and_gravatar_graph(monkeypatch) -> None:
    captured = {'image_count': 0, 'usernames': []}

    monkeypatch.setattr(services, 'username_adapter', lambda u: [])
    monkeypatch.setattr(
        services,
        'email_adapter',
        lambda e: [
            {
                'email': 'alice@gmail.com',
                'domain': 'gmail.com',
                'mx_records': ['mx.google.com'],
                'txt_records_count': 1,
                'spf_record': 'v=spf1 include:_spf.google.com ~all',
                'dmarc_record': 'v=DMARC1; p=none',
                'gravatar_url': 'https://www.gravatar.com/avatar/abc',
                'has_gravatar': True,
                'possible_usernames': ['alice'],
                'breach_sources': [],
                'deliverability_confidence': 0.9,
            }
        ],
    )

    def _image_analysis(contents, consent):
        captured['image_count'] = len(contents)
        return {'uploaded': bool(contents), 'image_count': len(contents), 'reverse_matches': [], 'geo_hints': []}

    monkeypatch.setattr(services, 'run_image_analysis', _image_analysis)
    def _similar_accounts(usernames, known):
        captured['usernames'] = usernames
        return []

    monkeypatch.setattr(services, 'similar_accounts_ai', _similar_accounts)
    monkeypatch.setattr(services, 'persist_graph_neo4j', lambda case_id, graph: None)

    with TestClient(app) as client:
        auth = client.post(
            '/api/auth/token',
            data={'username': 'admin@local', 'password': 'admin123'},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

        files = [
            ('images', ('one.jpg', b'img1', 'image/jpeg')),
            ('images', ('two.jpg', b'img2', 'image/jpeg')),
        ]
        create = client.post(
            '/api/cases',
            data={
                'title': 'Cache test',
                'notes': '',
                'usernames': '',
                'emails': 'alice@gmail.com',
                'known_accounts': '',
                'legal_basis': 'public interest',
                'purpose': 'journalism',
                'consent_for_face_matching': 'false',
            },
            files=files,
            headers=headers,
        )
        assert create.status_code == 200
        case_id = create.json()['case_id']

        run = client.post(f'/api/cases/{case_id}/investigate', data={'images_b64_json': '[]'}, headers=headers)
        assert run.status_code == 200
        job_id = run.json()['job_id']

        deadline = time.time() + 5
        while time.time() < deadline:
            state = client.get(f'/api/jobs/{job_id}', headers=headers)
            payload = state.json()
            if payload['status'] == 'completed':
                graph_types = {n['type'] for n in payload['findings']['graph']['nodes']}
                assert 'Gravatar' in graph_types
                break
            time.sleep(0.2)

        assert captured['image_count'] == 2
        assert captured['usernames'] == ['alice']
