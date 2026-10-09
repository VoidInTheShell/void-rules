from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .artifacts import deterministic_gzip
from .errors import FetchError
from .publication import json_bytes

KEY = re.compile(r"[a-z0-9][a-z0-9-]*")
SHA256 = re.compile(r"[0-9a-f]{64}")


class InputStore:
    """Committed, hash-verified inputs, independent of the mutable .work cache."""

    def __init__(self, root: Path, group: str, *, required: bool = False) -> None:
        self.root = root
        self.directory = f"generated/inputs/{group}"
        self.entries: dict[str, dict[str, Any]] = {}
        self.captured: dict[str, tuple[bytes, dict[str, Any]]] = {}
        index = root / self.directory / "index.json"
        if not index.exists() and not required:
            return
        try:
            document = json.loads(index.read_bytes())
            if document["version"] != 1 or not isinstance(document["entries"], dict):
                raise ValueError("invalid input index")
            for key, entry in document["entries"].items():
                if (
                    not KEY.fullmatch(key)
                    or not isinstance(entry, dict)
                    or not SHA256.fullmatch(str(entry.get("sha256", "")))
                    or type(entry.get("size")) is not int
                    or not 0 <= entry["size"] <= 100 * 1024 * 1024
                    or not isinstance(entry.get("metadata"), dict)
                ):
                    raise ValueError(f"invalid input entry: {key}")
            self.entries = document["entries"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise FetchError(f"cannot read locked inputs {index}: {exc}") from exc

    def read(self, key: str) -> tuple[bytes, dict[str, Any]]:
        entry = self.entries.get(key)
        if entry is None:
            raise FetchError(f"locked input is missing: {self.directory}/{key}")
        path = self.root / self.directory / f"{key}.gz"
        try:
            with gzip.open(path, "rb") as stream:
                data = stream.read(entry["size"] + 1)
        except (OSError, EOFError) as exc:
            raise FetchError(f"cannot read locked input {path}: {exc}") from exc
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise FetchError(f"locked input checksum/size mismatch: {path}")
        return data, dict(entry["metadata"])

    def capture(self, key: str, data: bytes, metadata: dict[str, Any]) -> None:
        if not KEY.fullmatch(key):
            raise FetchError(f"invalid input key: {key}")
        self.captured[key] = (data, metadata)

    def files(self) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        entries = {}
        for key, (data, metadata) in sorted(self.captured.items()):
            files[f"{self.directory}/{key}.gz"] = deterministic_gzip(data, self.root)
            entries[key] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "metadata": metadata,
            }
        files[f"{self.directory}/index.json"] = json_bytes({"version": 1, "entries": entries})
        return files
