FROM python:3.12-slim-trixie

ARG TARGETPLATFORM=linux/amd64
ARG TARGETARCH

ARG GHIDRA_DIST_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip
ARG GHIDRA_DIST_SHA256=c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120

ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

RUN image_arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    image_platform="${TARGETPLATFORM:-linux/${image_arch}}"; \
    if [ "${image_arch}" != "amd64" ]; then \
      echo >&2 "Error: Ghidra Linux decompiler support in this image requires linux/amd64, but Docker is building for '${image_platform}'."; \
      echo >&2 "Hint: set DOCKER_PLATFORM=linux/amd64 or build with ./build_docker_image.sh."; \
      exit 1; \
    fi

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    openjdk-21-jdk-headless \
    unzip \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /tmp/ghidra /opt /data/projects /samples \
 && curl -L "${GHIDRA_DIST_URL}" -o /tmp/ghidra/ghidra.zip \
 && echo "${GHIDRA_DIST_SHA256}  /tmp/ghidra/ghidra.zip" | sha256sum -c - \
 && unzip -q /tmp/ghidra/ghidra.zip -d /opt \
 && mv "$(find /opt -mindepth 1 -maxdepth 1 -type d -name 'ghidra_*' | head -n 1)" "${GHIDRA_INSTALL_DIR}" \
 && rm -rf /tmp/ghidra

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md /app/
COPY src /app/src
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN uv sync --frozen
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

EXPOSE 8081

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uv", "run", "ghidra-mcp", "--project-location", "/data/projects", "--project-name", "default", "--transport", "http", "--mcp-host", "0.0.0.0", "--mcp-port", "8081", "--mcp-path", "/mcp"]
