# QuantumSafe backend API image.
FROM python:3.12-slim

# git is needed for `quantumsafe scan --repo <github url>`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the shared scanner package first (better layer caching).
COPY pyproject.toml README.md ./
COPY cli/ ./cli/
RUN pip install --no-cache-dir -e .

# Backend dependencies.
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Application code.
COPY backend/ ./backend/

ENV PYTHONUNBUFFERED=1
EXPOSE 5000
WORKDIR /app/backend
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--timeout", "120"]
