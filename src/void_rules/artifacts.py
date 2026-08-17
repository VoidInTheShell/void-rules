from __future__ import annotations

from pathlib import Path

from .codecs import GeodataCodec


def deterministic_gzip(data: bytes, root: Path) -> bytes:
    """Compress through the pinned Go toolchain for cross-platform byte stability."""

    return GeodataCodec(root).gzip(data)
