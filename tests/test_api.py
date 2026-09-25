from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get('/')
    assert response.status_code == 200
    assert response.json()['message']


def test_login_and_profile_flow():
    login_response = client.post(
        '/token',
        data={'username': 'admin@aoca.com', 'password': 'admin123'},
    )
    assert login_response.status_code == 200
    payload = login_response.json()
    assert 'access_token' in payload
    assert payload['user']['role'] == 'admin'

    profile_response = client.get(
        '/users/me',
        headers={'Authorization': f"Bearer {payload['access_token']}"},
    )
    assert profile_response.status_code == 200
    assert profile_response.json()['role'] == 'admin'


def test_jobs_and_application_flow():
    jobs_response = client.get('/careers/jobs')
    assert jobs_response.status_code == 200
    jobs = jobs_response.json()['jobs']
    assert len(jobs) > 0

    job_id = jobs[0]['_id']
    apply_response = client.post(
        f'/careers/jobs/{job_id}/apply',
        json={
            'first_name': 'Jane',
            'last_name': 'Doe',
            'email': 'jane@example.com',
            'phone': '+2348000000000',
            'resume_url': 'https://example.com/resume.pdf',
            'cover_letter': 'Interested in this role.',
        },
    )
    assert apply_response.status_code == 200
    body = apply_response.json()
    assert body['status'] == 'applied'


def test_admin_stats_endpoint():
    login_response = client.post(
        '/token',
        data={'username': 'admin@aoca.com', 'password': 'admin123'},
    )
    assert login_response.status_code == 200
    token = login_response.json()['access_token']

    admin_response = client.get(
        '/admin/dashboard/stats',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert admin_response.status_code == 200
    data = admin_response.json()
    assert 'users' in data
    assert 'careers' in data
