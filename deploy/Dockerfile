FROM ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv openvpn openssl iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=secret,id=proxy_ca \
    python3 -m venv /opt/venv && \
    if [ -f /run/secrets/proxy_ca ]; then \
      PIP_CERT=/run/secrets/proxy_ca /opt/venv/bin/pip install --no-cache-dir -r requirements.txt; \
    else /opt/venv/bin/pip install --no-cache-dir -r requirements.txt; fi
COPY openvpnpa ./openvpnpa
ENV PATH="/opt/venv/bin:${PATH}"
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "openvpnpa.app"]
