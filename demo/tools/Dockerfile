# afw-demo-tools: one small image for every fake piece of the demo (PKI job, fake upstreams, plain agents).
# Build: docker build -t afw-demo-tools:local demo/tools
FROM python:3.12-alpine3.20
RUN apk add --no-cache bash curl jq openssl bind-tools netcat-openbsd iproute2 ca-certificates postgresql16-client
COPY fake_upstream.py pki.sh /opt/afw-demo/
RUN chmod 0755 /opt/afw-demo/pki.sh /opt/afw-demo/fake_upstream.py
LABEL org.opencontainers.image.title="afw-demo-tools" \
      org.opencontainers.image.description="agents-firewall demo: fake upstreams, demo PKI, test agents" \
      org.opencontainers.image.licenses="Apache-2.0"
CMD ["sleep", "infinity"]
