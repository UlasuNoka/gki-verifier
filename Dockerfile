FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    lz4 \
    zstd \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GKI_MAX_UPLOAD_MB=512

WORKDIR /app
COPY gki_verifier /app/gki_verifier

EXPOSE 8080

ENTRYPOINT ["python3", "-u", "-m", "gki_verifier"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
