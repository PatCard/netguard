# --- Stage 1: builder ---
FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: runtime ---
FROM python:3.11-slim

WORKDIR /app

# Instalar nmap en runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

# Copiar dependencias instaladas desde builder
COPY --from=builder /install /usr/local

# Copiar código fuente
COPY . .

EXPOSE 5000

CMD ["python", "main.py"]