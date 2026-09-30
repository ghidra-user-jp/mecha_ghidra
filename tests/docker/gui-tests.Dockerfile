# The Ghidra GUI acceptance tests on Linux (tests/test_gui_integration.py and
# tests/test_gui_relay_integration.py) from a machine without Linux, a Mac for
# one: the product image plus a display-capable JRE, Xvfb and the test
# dependencies of the lock file. CI runs them on an Ubuntu runner instead.
# The checkout to test is mounted at /work; see run_gui_tests.sh.
ARG BASE_IMAGE=mecha_ghidra:ci
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-21-jre xvfb xauth \
 && rm -rf /var/lib/apt/lists/*
RUN uv sync --frozen --no-dev --extra dev
USER ghidra
ENTRYPOINT []
CMD ["sh", "/work/tests/docker/run_gui_tests.sh"]
