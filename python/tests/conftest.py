"""Shared helpers for the dryoc test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

# Known-answer vectors vendored in the Rust crate (repository checkout only).
RUST_VECTORS = Path(__file__).resolve().parents[2] / "src" / "mlkem" / "test-vectors"


def load_vectors(name: str) -> list[dict[str, str]]:
    """Parses a ``key = value`` record file from the Rust crate's vectors.

    Records are separated by blank lines; ``#`` lines are comments. Skips the
    calling test when the repository's vector directory is not available
    (for example, when testing an unpacked sdist).
    """
    path = RUST_VECTORS / name
    if not path.is_file():
        pytest.skip(f"Rust test vectors not found at {path} (not a repository checkout)")
    records: list[dict[str, str]] = [{}]
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            continue
        if not line:
            if records[-1]:
                records.append({})
            continue
        key, value = line.split(" = ", 1)
        assert key not in records[-1], f"repeated key {key} in {name}"
        records[-1][key] = value
    return [record for record in records if record]


def flip(data: bytes, index: int = 0, mask: int = 0x01) -> bytes:
    """Returns ``data`` with one bit flipped at ``index``."""
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


BUFFER_TYPES = [
    pytest.param(bytes, id="bytes"),
    pytest.param(bytearray, id="bytearray"),
    pytest.param(lambda data: memoryview(bytes(data)), id="memoryview"),
    pytest.param(lambda data: memoryview(bytearray(b"xx" + data))[2:], id="memoryview-slice"),
]
"""Constructors for every bytes-like input kind the API must accept."""
