# One container: FastAPI backend + static frontend. FalkorDB runs separately.
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY frontend frontend
WORKDIR /app/backend
# Render/Railway inject $PORT; default to 8042 locally.
# SEED_ON_START=true reloads the demo data every time the container starts.
CMD ["sh", "-c", "if [ \"$SEED_ON_START\" = true ]; then python setup_db.py; fi; exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8042}"]
