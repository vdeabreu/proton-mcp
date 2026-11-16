# Base image pinned by digest (the tag is on the FROM line); Dependabot proposes updates.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
WORKDIR /app
RUN pip install --no-cache-dir "mcp==2.3.0" "uvicorn==0.54.0" \
    && useradd -u 1000 -m app && mkdir /data && chown app /data
COPY proton_mcp.py remote/auth.py remote/server.py ./
USER app
ENV DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8766\")}/health')"
CMD ["python", "server.py"]
