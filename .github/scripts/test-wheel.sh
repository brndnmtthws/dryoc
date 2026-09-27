#!/bin/sh
# Test a prebuilt wheel against the Python test suite. Run from python/.
#
# Usage: test-wheel.sh PYTHON WHEEL_GLOB
#
# Recreates the project environment for PYTHON with only the locked test
# group, installs the wheel into it (`--no-sync` keeps uv from building the
# project) and checks that the tests import the installed package, not the
# sources in the checkout. On a free-threaded interpreter, importing dryoc
# must leave the GIL disabled.
set -eu

python="$1"
wheel_glob="$2"

uv sync --locked --only-group test --python "$python"
# Unquoted on purpose: the glob expands to the one matching wheel. A glob
# without a match stays literal and uv reports the missing file.
# shellcheck disable=SC2086
uv pip install $wheel_glob
uv run --no-sync python -c "import dryoc; assert 'site-packages' in dryoc.__file__, dryoc.__file__"
uv run --no-sync python -c "import sys, sysconfig, dryoc; assert not (sysconfig.get_config_var('Py_GIL_DISABLED') and sys._is_gil_enabled())"
uv run --no-sync python -c "import nacl"
uv run --no-sync pytest -p no:cacheprovider tests
