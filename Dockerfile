FROM python:3.12-slim-trixie

ARG TARGETPLATFORM=linux/amd64
ARG TARGETARCH

ARG GHIDRA_DIST_URL
ARG GHIDRA_DIST_SHA256
ARG GHIDRA_DECOMPILER_NATIVES_URL
ARG GHIDRA_DECOMPILER_NATIVES_SHA256
ARG GHIDRA_DIST_URL_AMD64_DEFAULT=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
ARG GHIDRA_DIST_SHA256_AMD64_DEFAULT=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
ARG GHIDRA_DECOMPILER_NATIVES_URL_ARM64_DEFAULT=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/v1.0.1/ghidra_decompiler_natives_all.zip
ARG GHIDRA_DECOMPILER_NATIVES_SHA256_ARM64_DEFAULT=3a8de764a310c7542442978da1cd9cb463861ce9fb345275f2a00c60cdb5c7c6

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
    mkdir -p /tmp/ghidra /opt /data/projects /data/exports /data/scripts /samples; \
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
    curl -fsSL --retry 3 "${ghidra_dist_url}" -o /tmp/ghidra/ghidra.zip; \
    echo "${ghidra_dist_sha256}  /tmp/ghidra/ghidra.zip" | sha256sum -c -; \
    unzip -q /tmp/ghidra/ghidra.zip -d /opt; \
    mv "$(find /opt -mindepth 1 -maxdepth 1 -type d -name 'ghidra_*' | head -n 1)" "${GHIDRA_INSTALL_DIR}"; \
    if [ -n "${ghidra_decompiler_natives_url}" ]; then \
      echo "Using decompiler natives overlay: ${ghidra_decompiler_natives_url}"; \
      curl -fsSL --retry 3 "${ghidra_decompiler_natives_url}" -o /tmp/ghidra/decompiler-natives.zip; \
      echo "${ghidra_decompiler_natives_sha256}  /tmp/ghidra/decompiler-natives.zip" | sha256sum -c -; \
      unzip -q /tmp/ghidra/decompiler-natives.zip 'Ghidra/Features/Decompiler/os/linux_arm_64/*' -d "${GHIDRA_INSTALL_DIR}"; \
      chmod 0755 "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/sleigh"; \
    fi; \
    if [ "${image_arch}" = "arm64" ] && { [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" ] || [ ! -x "${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/sleigh" ]; }; then \
      echo >&2 "Error: linux/arm64 Docker builds require a Ghidra distribution that already contains Ghidra/Features/Decompiler/os/linux_arm_64/{decompile,sleigh}."; \
      echo >&2 "Hint: use the default decompiler natives overlay or set GHIDRA_DECOMPILER_NATIVES_URL and GHIDRA_DECOMPILER_NATIVES_SHA256 for an overlay matching the Ghidra distribution."; \
      exit 1; \
    fi; \
    jython_zip="$(find "${GHIDRA_INSTALL_DIR}/Extensions/Ghidra" -maxdepth 1 -name '*_Jython.zip' | head -n 1)"; \
    if [ -n "${jython_zip}" ]; then \
      mkdir -p "${GHIDRA_INSTALL_DIR}/Ghidra/Extensions"; \
      unzip -q "${jython_zip}" -d "${GHIDRA_INSTALL_DIR}/Ghidra/Extensions"; \
    fi; \
    rm -rf /tmp/ghidra

RUN pip install --no-cache-dir uv==0.11.2

WORKDIR /app

# Dependencies first: a source edit must not invalidate the pyghidra/mcp layer.
COPY pyproject.toml uv.lock README.md LICENSE /app/
RUN uv sync --frozen --no-install-project --no-dev

COPY src /app/src
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN uv sync --frozen --no-dev \
 && chmod 0755 /usr/local/bin/docker-entrypoint.sh

# The server imports untrusted binaries and drives a JVM; it must not run as root.
RUN groupadd --system --gid 10001 ghidra \
 && useradd --system --uid 10001 --gid ghidra --home-dir /home/ghidra --create-home ghidra \
 && chown -R ghidra:ghidra /data /samples /home/ghidra
USER ghidra
ENV HOME=/home/ghidra

EXPOSE 8081

# A TCP-level probe checks the listener, not JVM health or tool execution.
# The stateless MCP endpoint accepts JSON-RPC POST requests, not a plain GET.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1', 8081), timeout=3); s.close()" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
# --no-sync: the environment is fully built above; never resolve at start-up.
# Import, project and export roots are pinned to the mounted volumes so an MCP
# client cannot read or write outside them.  Scripts stay disabled: add
# "--add-category", "scripts", "--script-root", "/data/scripts" (mounted
# read-only) to expose and enable the scripts tools.
CMD ["uv", "run", "--frozen", "--no-sync", "mecha_ghidra", \
     "--project-location", "/data/projects", "--project-name", "default", \
     "--allowed-import-root", "/samples", "--allowed-project-root", "/data/projects", \
     "--allowed-export-root", "/data/exports", \
     "--transport", "http", "--mcp-host", "0.0.0.0", "--mcp-port", "8081", "--mcp-path", "/mcp"]
