How to run locally

1) Ensure backend deps are available (uses in-repo FastAPI app):

   cd gui/backend && python3 -m venv venv && ./venv/bin/pip install -U pip fastapi uvicorn pytest httpx starlette

2) From repo root:

   python3 -m pytest -q tests/api


