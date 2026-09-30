"""Catch missing or changed bundled inputs even when real-Ghidra tests are disabled."""

import hashlib

from binary_fixtures import GHIDRA_EXERCISE_PE


def test_bundled_ghidra_exercise_matches_the_distribution():
    assert hashlib.sha256(GHIDRA_EXERCISE_PE.read_bytes()).hexdigest() == (
        "7a98a934de5f578c3a547af873221b221d037bafa87ceee71dd4f089dd228202"
    )
