"""Pytest configuration and test environment setup.

Ensures that when running in headless CI or environments where ViGEmBus
driver is not installed, importing vgamepad does not fail during test collection.
"""

from __future__ import annotations

import vgamepad_compat  # noqa: F401
