# Använd en officiell Python-bild som basimage
FROM python:3.11-slim

# Sätt arbetskatalogen i containern
WORKDIR /app

# Installera systempaket som behövs
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Kopiera kravfilen och installera beroenden
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiera resten av projektet till /app
COPY . .

# Skapa en mapp för temporära filer
RUN mkdir -p /app/tmp

# Exponera port 5000 (standardport för Flask)
EXPOSE 5000

# Sätt miljövariabler för produktion
ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Standardvärden för icke-känsliga miljövariabler
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    RATE_LIMIT_DEFAULT="200 per minute, 1000 per hour"

# Skapa en hälsokontrollsfil
RUN echo "from flask import Flask\napp = Flask(__name__)\n@app.route('/health')\ndef health():\n    return {'status': 'healthy'}\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', port=8080)" > /app/healthcheck.py

# Starta applikationen med Gunicorn
# Känsliga miljövariabler ska tillhandahållas vid körning med docker run -e eller i docker-compose.yml
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "eventlet", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
