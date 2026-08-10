"""Shared fixtures.

The repo cache in `publish` is module state that outlives a single test, so
isolating it is not tidiness -- a warm entry can satisfy a later test's fetch,
and a test asserting a fetch FAILURE would then pass without the failure ever
occurring. Autouse so a new test file cannot forget it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import publish  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_repo_cache():
    publish.reset_repo_cache()
    yield
    publish.reset_repo_cache()
