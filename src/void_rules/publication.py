from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import BuildError
from .fetch import write_bytes_atomic


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def obsolete_files(root: Path, files: dict[str, bytes], directories: list[str]) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for directory in directories
        for path in (root / directory).rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in files
    }


def changed_files(root: Path, files: dict[str, bytes], removed: set[str]) -> set[str]:
    return removed | {
        name
        for name, data in files.items()
        if not (root / name).is_file() or (root / name).read_bytes() != data
    }


def publish_files(root: Path, files: dict[str, bytes], removed: set[str]) -> None:
    """Stage the complete result, then publish with rollback on filesystem errors."""
    changed = changed_files(root, files, removed)
    originals: dict[str, bytes | None] = {}
    for name in sorted(changed):
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise BuildError(f"unsafe publication target: {name}")
        originals[name] = path.read_bytes() if path.is_file() else None
    stage_root = root / ".work" / "staging"
    stage_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=stage_root) as temporary:
        stage = Path(temporary)
        for name in changed - removed:
            write_bytes_atomic(stage / name, files[name])
        applied: list[str] = []
        try:
            for name in sorted(changed):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if name in removed:
                    target.unlink()
                else:
                    os.replace(stage / name, target)
                applied.append(name)
        except OSError:
            for name in reversed(applied):
                original = originals[name]
                if original is None:
                    (root / name).unlink(missing_ok=True)
                else:
                    write_bytes_atomic(root / name, original)
            raise


def publication_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for directory in ("dist", "generated"):
        for path in sorted((root / directory).rglob("*")):
            if path.is_file():
                digest.update(path.relative_to(root).as_posix().encode() + b"\0")
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
