FROM python:3.11-slim

LABEL maintainer="Mini SOC Team"
LABEL description="Dionaea Multi-Protocol Malware Trap for ARM64"

WORKDIR /opt/dionaea

RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-traditional \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/dionaea/

RUN mkdir -p /opt/dionaea/var/log /opt/dionaea/var/dionaea/binaries

EXPOSE 445 80 21 69

ENTRYPOINT ["python3", "/opt/dionaea/service.py"]

