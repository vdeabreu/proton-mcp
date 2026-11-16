# Base image pinned by digest (python:3.12-slim); Dependabot proposes updates.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
RUN pip install --no-cache-dir "mcp==2.3.0" "uvicorn==0.54.0" \
    && useradd -u 1000 -m app && mkdir /data && chown app /data
COPY proton_mcp.py remote/auth.py remote/server.py ./
USER app
ENV DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8766\")}/health')"
CMD ["python", "server.py"]
