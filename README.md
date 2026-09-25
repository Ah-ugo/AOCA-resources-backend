# AOCA Resources Backend (scaffold)

This is a minimal FastAPI scaffold to run the AOCA Resources API locally.

Prerequisites:

- Python 3.10+
- MongoDB running locally or remote, set `MONGO_URL` in `.env`

Setup:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env to set MONGO_URL and SECRET_KEY
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000/docs to view the OpenAPI docs.
