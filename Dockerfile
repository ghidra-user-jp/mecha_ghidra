FROM python:3.12-slim-trixie

ARG TARGETPLATFORM=linux/amd64
ARG TARGETARCH

ARG GHIDRA_DIST_URL
ARG GHIDRA_DIST_SHA256
ARG GHIDRA_DIST_URL_AMD64_DEFAULT=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1_build/ghidra_12.1_PUBLIC_20260513.zip
ARG GHIDRA_DIST_SHA256_AMD64_DEFAULT=aa5cbcbbf48f41ca185fce900e19592f1ade4cd5994eb6e0ede468dac8a6f302
ARG GHIDRA_DIST_URL_ARM64_DEFAULT=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/v0.1.2/mecha_ghidra_docker_arm64_ghidra_12.1_patched.zip
ARG GHIDRA_DIST_SHA256_ARM64_DEFAULT=be573228d23e0c7cc2217e768667ef2478d7e673e68ae4e2fa6dddec072d3494

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

RUN set -eu; \
    mkdir -p /tmp/ghidra /opt /data/projects /samples; \
    image_arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    ghidra_dist_url="${GHIDRA_DIST_URL:-}"; \
    ghidra_dist_sha256="${GHIDRA_DIST_SHA256:-}"; \
    if [ -n "${ghidra_dist_url}" ] || [ -n "${ghidra_dist_sha256}" ]; then \
      if [ -z "${ghidra_dist_url}" ] || [ -z "${ghidra_dist_sha256}" ]; then \
        echo >&2 "Error: GHIDRA_DIST_URL and GHIDRA_DIST_SHA256 must be provided together when overriding the bundled Ghidra distribution."; \
        exit 1; \
      fi; \
    else \
      case "${image_arch}" in \
        amd64) \
          ghidra_dist_url="${GHIDRA_DIST_URL_AMD64_DEFAULT}"; \
          ghidra_dist_sha256="${GHIDRA_DIST_SHA256_AMD64_DEFAULT}"; \
          ;; \
        arm64) \
          ghidra_dist_url="${GHIDRA_DIST_URL_ARM64_DEFAULT}"; \
          ghidra_dist_sha256="${GHIDRA_DIST_SHA256_ARM64_DEFAULT}"; \
          ;; \
      esac; \
    fi; \
    echo "Using Ghidra distribution: ${ghidra_dist_url}"; \
    curl -L "${ghidra_dist_url}" -o /tmp/ghidra/ghidra.zip; \
    echo "${ghidra_dist_sha256}  /tmp/ghidra/ghidra.zip" | sha256sum -c -; \
    unzip -q /tmp/ghidra/ghidra.zip -d /opt; \
    mv "$(find /opt -mindepth 1 -maxdepth 1 -type d -name 'ghidra_*' | head -n 1)" "${GHIDRA_INSTALL_DIR}"; \
    if [ "${image_arch}" = "arm64" ] && { [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" ] || [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/sleigh" ]; }; then \
      echo >&2 "Error: linux/arm64 Docker builds require a Ghidra distribution that already contains Ghidra/Features/Decompiler/os/linux_arm_64/{decompile,sleigh}."; \
      echo >&2 "Hint: the default linux/arm64 build uses the mecha_ghidra patched distribution release artifact. If you overrode GHIDRA_DIST_URL, point it at a patched ARM64 Ghidra ZIP or apply the linux_arm_64 overlay before building."; \
      exit 1; \
    fi; \
    rm -rf /tmp/ghidra

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
