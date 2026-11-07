FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    XRAYSUBFORGE_CONFIG=/data/config.json \
    XRAYSUBFORGE_HOST=0.0.0.0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py gunicorn.conf.py ./
COPY xraysubforge ./xraysubforge

RUN useradd --system --uid 10001 xraysubforge && mkdir -p /data && chown xraysubforge /data
USER xraysubforge
VOLUME /data
EXPOSE 8080

# address, port and worker counts come from gunicorn.conf.py, which reads server.* in config.json
# (no access log on purpose: URLs contain each user's secret subscription id)
CMD ["gunicorn", "app:app"]
