from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .errors import CodecError


def _run(command: list[str], *, cwd: Path, timeout: int = 180) -> None:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CodecError(f"failed to run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        stderr = result.stderr.strip()[-4000:]
        stdout = result.stdout.strip()[-1000:]
        raise CodecError(
            f"codec command exited {result.returncode}: {' '.join(command)}\n"
            f"stdout: {stdout}\nstderr: {stderr}"
        )


class MihomoCodec:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def executable(self) -> Path:
        candidates: list[str | Path] = []
        configured = os.environ.get("VOID_RULES_MIHOMO")
        if configured:
            candidates.append(configured)
        candidates.extend(
            [
                self.root / ".tools" / "mihomo.exe",
                self.root / ".tools" / "mihomo",
            ]
        )
        located = shutil.which("mihomo")
        if located:
            candidates.append(located)
        for candidate in candidates:
            path = Path(candidate).expanduser().resolve()
            if path.is_file():
                return path
        raise CodecError(
            "Mihomo CLI is required for MRS output; set VOID_RULES_MIHOMO or install .tools/mihomo"
        )

    def decode(self, data: bytes, behavior: str) -> bytes:
        if behavior not in {"domain", "ipcidr"}:
            raise CodecError(f"MRS behavior must be domain or ipcidr, got {behavior!r}")
        with tempfile.TemporaryDirectory(prefix="void-rules-mrs-") as temp_dir:
            directory = Path(temp_dir)
            source = directory / "source.mrs"
            target = directory / "decoded.txt"
            source.write_bytes(data)
            _run(
                [
                    str(self.executable()),
                    "convert-ruleset",
                    behavior,
                    "mrs",
                    str(source),
                    str(target),
                ],
                cwd=self.root,
            )
            if not target.is_file():
                raise CodecError("Mihomo did not create decoded MRS output")
            return target.read_bytes()

    def encode(self, text: bytes, behavior: str) -> bytes:
        if behavior not in {"domain", "ipcidr"}:
            raise CodecError(f"MRS behavior must be domain or ipcidr, got {behavior!r}")
        with tempfile.TemporaryDirectory(prefix="void-rules-mrs-") as temp_dir:
            directory = Path(temp_dir)
            source = directory / "source.txt"
            target = directory / "encoded.mrs"
            source.write_bytes(text)
            _run(
                [
                    str(self.executable()),
                    "convert-ruleset",
                    behavior,
                    "text",
                    str(source),
                    str(target),
                ],
                cwd=self.root,
            )
            if not target.is_file():
                raise CodecError("Mihomo did not create encoded MRS output")
            return target.read_bytes()


class GeodataCodec:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def executable(self) -> Path:
        configured = os.environ.get("VOID_RULES_GEODATA")
        if configured:
            path = Path(configured).expanduser().resolve()
            if path.is_file():
                return path
            raise CodecError(f"VOID_RULES_GEODATA does not exist: {path}")
        suffix = ".exe" if os.name == "nt" else ""
        target = self.root / ".work" / "tools" / f"void-rules-geodata{suffix}"
        source_dir = self.root / "cmd" / "void-rules-geodata"
        newest_source = max(path.stat().st_mtime_ns for path in source_dir.glob("*.go"))
        if not target.exists() or target.stat().st_mtime_ns < newest_source:
            target.parent.mkdir(parents=True, exist_ok=True)
            _run(["go", "build", "-trimpath", "-o", str(target), "."], cwd=source_dir, timeout=300)
        return target

    def _convert(
        self,
        command: str,
        *,
        input_bytes: bytes,
        tags: tuple[str, ...] = (),
    ) -> bytes:
        with tempfile.TemporaryDirectory(prefix="void-rules-geodata-") as temp_dir:
            directory = Path(temp_dir)
            source = directory / "input.bin"
            target = directory / "output.bin"
            source.write_bytes(input_bytes)
            arguments = [
                str(self.executable()),
                command,
                "-input",
                str(source),
                "-output",
                str(target),
            ]
            if tags:
                arguments.extend(["-tags", ",".join(tags)])
            _run(arguments, cwd=self.root, timeout=300)
            if not target.is_file():
                raise CodecError(f"geodata codec did not create output for {command}")
            return target.read_bytes()

    def decode(self, data: bytes, kind: str, tags: tuple[str, ...] = ()) -> list[dict[str, Any]]:
        command = "decode-geosite" if kind == "geosite" else "decode-geoip"
        payload = self._convert(command, input_bytes=data, tags=tags)
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(payload.decode("utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CodecError(f"invalid geodata JSONL line {line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise CodecError(f"invalid geodata JSONL object at line {line_number}")
            records.append(value)
        return records

    def encode(self, records: list[dict[str, Any]], kind: str) -> bytes:
        payload = "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ).encode()
        command = "encode-geosite" if kind == "geosite" else "encode-geoip"
        return self._convert(command, input_bytes=payload)
