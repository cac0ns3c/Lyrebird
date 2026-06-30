FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY config ./config
ENV PYTHONPATH=/app/src

# Drop privileges where possible; privileged ports (<1024) need either root or
# NET_BIND_SERVICE, granted in docker-compose.
ENTRYPOINT ["python", "-m", "lyrebird", "--config", "config/lyrebird.yaml"]
