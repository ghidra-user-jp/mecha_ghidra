#!/bin/sh
# Inside the GUI test image: start Xvfb, then run the GUI acceptance tests of the checkout mounted at /work.
# Projects, settings and registries go to /tmp, the container's own filesystem: a bind mount's file locks
# do not stop a second process (spec §14.2).
set -eu
Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp > /tmp/xvfb.log 2>&1 &
xvfb=$!
i=0
while [ ! -S /tmp/.X11-unix/X99 ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
export DISPLAY=:99 GHIDRA_GUI_VALIDATION=1 GHIDRA_INSTALL_DIR=/opt/ghidra PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=/work/src:/work/tests
cd /work
status=0
/app/.venv/bin/python -m pytest -p no:cacheprovider -q -rfE --basetemp=/tmp/gui-it \
  tests/test_gui_integration.py tests/test_gui_relay_integration.py "$@" || status=$?
kill "$xvfb" 2>/dev/null || true
exit "$status"
