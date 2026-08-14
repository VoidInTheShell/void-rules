from __future__ import annotations

import gzip
import io


def deterministic_gzip(data: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=buffer,
        mtime=0,
    ) as archive:
        archive.write(data)
    return buffer.getvalue()
