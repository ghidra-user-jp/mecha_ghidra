FROM python:3.12-slim-trixie

ARG TARGETPLATFORM=linux/amd64
ARG TARGETARCH

ARG GHIDRA_DIST_URL
ARG GHIDRA_DIST_SHA256
ARG GHIDRA_DECOMPILER_NATIVES_URL
ARG GHIDRA_DECOMPILER_NATIVES_SHA256
ARG GHIDRA_DIST_URL_AMD64_DEFAULT=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip
ARG GHIDRA_DIST_SHA256_AMD64_DEFAULT=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
ARG GHIDRA_DECOMPILER_NATIVES_URL_ARM64_DEFAULT=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/v0.1.2-rc.1/ghidra_decompiler_natives_all.zip
ARG GHIDRA_DECOMPILER_NATIVES_SHA256_ARM64_DEFAULT=4ef6afb1b73d954cb7e3ee2d780f4bb321f04b68b97769f9b0405e33e43f14e5

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
    ghidra_dist_overridden=0; \
    ghidra_decompiler_natives_url="${GHIDRA_DECOMPILER_NATIVES_URL:-}"; \
    ghidra_decompiler_natives_sha256="${GHIDRA_DECOMPILER_NATIVES_SHA256:-}"; \
    if [ -n "${ghidra_dist_url}" ] || [ -n "${ghidra_dist_sha256}" ]; then \
      if [ -z "${ghidra_dist_url}" ] || [ -z "${ghidra_dist_sha256}" ]; then \
        echo >&2 "Error: GHIDRA_DIST_URL and GHIDRA_DIST_SHA256 must be provided together when overriding the bundled Ghidra distribution."; \
        exit 1; \
      fi; \
      ghidra_dist_overridden=1; \
    else \
      ghidra_dist_url="${GHIDRA_DIST_URL_AMD64_DEFAULT}"; \
      ghidra_dist_sha256="${GHIDRA_DIST_SHA256_AMD64_DEFAULT}"; \
    fi; \
    if [ -n "${ghidra_decompiler_natives_url}" ] || [ -n "${ghidra_decompiler_natives_sha256}" ]; then \
      if [ -z "${ghidra_decompiler_natives_url}" ] || [ -z "${ghidra_decompiler_natives_sha256}" ]; then \
        echo >&2 "Error: GHIDRA_DECOMPILER_NATIVES_URL and GHIDRA_DECOMPILER_NATIVES_SHA256 must be provided together when overriding the decompiler natives overlay."; \
        exit 1; \
      fi; \
    elif [ "${image_arch}" = "arm64" ] && [ "${ghidra_dist_overridden}" = "0" ]; then \
      ghidra_decompiler_natives_url="${GHIDRA_DECOMPILER_NATIVES_URL_ARM64_DEFAULT}"; \
      ghidra_decompiler_natives_sha256="${GHIDRA_DECOMPILER_NATIVES_SHA256_ARM64_DEFAULT}"; \
    fi; \
    echo "Using Ghidra distribution: ${ghidra_dist_url}"; \
    curl -L "${ghidra_dist_url}" -o /tmp/ghidra/ghidra.zip; \
    echo "${ghidra_dist_sha256}  /tmp/ghidra/ghidra.zip" | sha256sum -c -; \
    unzip -q /tmp/ghidra/ghidra.zip -d /opt; \
    mv "$(find /opt -mindepth 1 -maxdepth 1 -type d -name 'ghidra_*' | head -n 1)" "${GHIDRA_INSTALL_DIR}"; \
    if [ -n "${ghidra_decompiler_natives_url}" ]; then \
      echo "Using decompiler natives overlay: ${ghidra_decompiler_natives_url}"; \
      curl -L "${ghidra_decompiler_natives_url}" -o /tmp/ghidra/decompiler-natives.zip; \
      echo "${ghidra_decompiler_natives_sha256}  /tmp/ghidra/decompiler-natives.zip" | sha256sum -c -; \
      unzip -q /tmp/ghidra/decompiler-natives.zip 'Ghidra/Features/Decompiler/os/linux_arm_64/*' -d "${GHIDRA_INSTALL_DIR}"; \
      chmod 0755 "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/sleigh"; \
    fi; \
    if [ "${image_arch}" = "arm64" ] && { [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" ] || [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/sleigh" ]; }; then \
      echo >&2 "Error: linux/arm64 Docker builds require a Ghidra distribution that already contains Ghidra/Features/Decompiler/os/linux_arm_64/{decompile,sleigh}."; \
      echo >&2 "Hint: use the default decompiler natives overlay or set GHIDRA_DECOMPILER_NATIVES_URL and GHIDRA_DECOMPILER_NATIVES_SHA256 for an overlay matching the Ghidra distribution."; \
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
