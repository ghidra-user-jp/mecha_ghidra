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
    case "${image_arch}" in \
      amd64|arm64) ;; \
      *) \
      echo >&2 "Error: unsupported Docker target platform '${image_platform}'."; \
      echo >&2 "Hint: use linux/amd64, or linux/arm64 with a Ghidra distribution that already contains linux_arm_64 decompiler binaries."; \
      exit 1; \
      ;; \
    esac

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
 && image_arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    if [ "${image_arch}" = "arm64" ] && { [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" ] || [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/sleigh" ]; }; then \
      echo >&2 "Error: linux/arm64 Docker builds require a Ghidra distribution that already contains Ghidra/Features/Decompiler/os/linux_arm_64/{decompile,sleigh}."; \
      echo >&2 "Hint: set GHIDRA_DIST_URL to the patched mecha_ghidra linux_arm_64 distribution release artifact, or apply the linux_arm_64 overlay before building this image."; \
      exit 1; \
    fi \
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
