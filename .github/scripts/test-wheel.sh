#!/bin/sh
# Test a prebuilt wheel against the Python test suite. Run from python/.
#
# Usage: test-wheel.sh PYTHON WHEEL_GLOB
#
# Recreates the project environment for PYTHON (a version such as 3.15, or
# 3.15t for the free-threaded build) with only the locked test group,
# installs the wheel into it (`--no-sync` keeps uv from building the project)
# and checks that the tests import the installed package, not the sources in
# the checkout. On a free-threaded interpreter, importing dryoc must leave the
# GIL disabled.
#
# PyNaCl, the libsodium oracle of the interoperability tests, publishes no
# wheel for free-threaded CPython 3.15 or newer, and its source build runs
# libsodium's autotools build, which Windows lacks. There it is left out and
# the interoperability tests skip themselves; the same abi3t wheel runs them
# on GIL-enabled CPython.
set -eu

python="$1"
wheel_glob="$2"

# `--python 3.15` also selects an installed 3.15t when the GIL-enabled build
# is missing, so install the requested build first, and check below that the
# environment got it.
case "$python" in
  *t) gil_disabled=1 ;;
  *) gil_disabled=0 ;;
esac
uv python install "$python"

no_pynacl=""
if uv run --no-project --python "$python" python -c 'import sys, sysconfig
sys.exit(not (sysconfig.get_config_var("Py_GIL_DISABLED") and sys.version_info >= (3, 15)))'; then
  no_pynacl="--no-install-package pynacl"
fi

# shellcheck disable=SC2086
uv sync --locked --only-group test --python "$python" $no_pynacl
# Unquoted on purpose: the glob expands to the one matching wheel. A glob
# without a match stays literal and uv reports the missing file.
# shellcheck disable=SC2086
uv pip install $wheel_glob
uv run --no-sync python -c "import sys, sysconfig; assert bool(sysconfig.get_config_var('Py_GIL_DISABLED')) == bool($gil_disabled), sys.version"
uv run --no-sync python -c "import dryoc; assert 'site-packages' in dryoc.__file__, dryoc.__file__"
uv run --no-sync python -c "import sys, sysconfig, dryoc; assert not (sysconfig.get_config_var('Py_GIL_DISABLED') and sys._is_gil_enabled())"
if [ -z "$no_pynacl" ]; then
  uv run --no-sync python -c "import nacl"
fi
uv run --no-sync pytest -p no:cacheprovider tests
