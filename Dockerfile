# Build a verified Go module release rather than downloading an unverified binary.
FROM golang:1.26-alpine AS subfinder
ARG SUBFINDER_VERSION=v2.17.0
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

FROM python:3.13-alpine
RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 app \
    && adduser -D -u 10001 -G app -h /app app \
    && mkdir -p /data /config \
    && chown app:app /data /config
COPY --from=subfinder /go/bin/subfinder /usr/local/bin/subfinder
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app app ./app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp DATA_DIR=/data PORT=8080
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"
CMD ["python", "-m", "app.server"]
