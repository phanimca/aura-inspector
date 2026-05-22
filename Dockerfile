# ── Stage 1: install deps ──────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install base + UI + optional AI packages together so the image is self-contained.
# The openai package is optional; omit it if you don't need AI analysis.
COPY requirements.txt requirements-ai.txt ./
RUN pip install --no-cache-dir --prefix=/install \
    -r requirements.txt \
    -r requirements-ai.txt

# ── Stage 2: lean runtime image ───────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Aura Inspector"
LABEL org.opencontainers.image.description="AI-powered Salesforce Experience Cloud security scanner"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy installed packages from the builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY src/ src/

# Gradio serves on 7860 by default
EXPOSE 7860

# Use a non-root user for runtime security
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

ENV PYTHONUNBUFFERED=1

CMD ["python", "src/ui/app.py"]
