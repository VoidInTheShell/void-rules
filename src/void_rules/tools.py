from __future__ import annotations

import gzip
import hashlib
import io
import os
import platform
import stat
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .errors import CodecError, FetchError
from .fetch import RestrictedRedirectHandler

TOOL_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    }
)


def _platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        architecture = "amd64"
    else:
        raise CodecError(f"no pinned Mihomo asset for architecture {machine!r}")
    if system not in {"windows", "linux"}:
        raise CodecError(f"no pinned Mihomo asset for operating system {system!r}")
    return f"{system}-{architecture}"


def _load_tools(root: Path) -> dict[str, Any]:
    path = root / "catalog" / "tools.yaml"
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CodecError(f"invalid tool catalog: {exc}") from exc
    if not isinstance(value, dict):
        raise CodecError("tool catalog must be a mapping")
    return value


def _download(url: str, expected_size: int) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in TOOL_DOWNLOAD_HOSTS:
        raise CodecError(f"pinned tool URL is not an approved GitHub HTTPS URL: {url}")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "void-rules-tool-installer/0.1"},
    )
    opener = urllib.request.build_opener(RestrictedRedirectHandler(TOOL_DOWNLOAD_HOSTS))
    try:
        with opener.open(request, timeout=120) as response:
            final_host = (urlparse(response.geturl()).hostname or "").lower()
            if final_host not in TOOL_DOWNLOAD_HOSTS:
                raise CodecError(f"Mihomo asset redirected to unapproved host: {final_host}")
            data = response.read(expected_size + 1)
    except (FetchError, OSError) as exc:
        raise CodecError(f"failed to download pinned Mihomo asset: {exc}") from exc
    if len(data) != expected_size:
        raise CodecError(
            f"Mihomo asset size mismatch: expected {expected_size}, received {len(data)}"
        )
    return bytes(data)


def _extract(data: bytes, archive_format: str, windows: bool) -> bytes:
    if archive_format == "gzip":
        try:
            return bytes(gzip.decompress(data))
        except OSError as exc:
            raise CodecError(f"invalid Mihomo gzip asset: {exc}") from exc
    if archive_format == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                candidates = [
                    item
                    for item in archive.infolist()
                    if not item.is_dir()
                    and Path(item.filename).name.lower().endswith(".exe" if windows else "mihomo")
                ]
                if len(candidates) != 1:
                    raise CodecError(
                        f"expected exactly one Mihomo binary in zip, found {len(candidates)}"
                    )
                member = candidates[0]
                if Path(member.filename).name != member.filename:
                    raise CodecError(
                        f"nested/path-bearing archive member is not allowed: {member.filename}"
                    )
                if member.file_size > 128 * 1024 * 1024:
                    raise CodecError("Mihomo binary exceeds extraction size limit")
                return bytes(archive.read(member))
        except zipfile.BadZipFile as exc:
            raise CodecError(f"invalid Mihomo zip asset: {exc}") from exc
    raise CodecError(f"unsupported Mihomo archive format: {archive_format}")


def install_mihomo(root: Path, *, force: bool = False) -> Path:
    root = root.resolve()
    key = _platform_key()
    tools = _load_tools(root)
    try:
        asset = tools["tools"]["mihomo"]["assets"][key]
        url = str(asset["url"])
        expected_sha = str(asset["sha256"])
        expected_size = int(asset["size"])
        archive_format = str(asset["format"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CodecError(f"missing or invalid Mihomo asset metadata for {key}") from exc
    target = root / ".tools" / ("mihomo.exe" if key.startswith("windows-") else "mihomo")
    if target.exists() and not force:
        return target
    archive = _download(url, expected_size)
    actual_sha = hashlib.sha256(archive).hexdigest()
    if actual_sha != expected_sha:
        raise CodecError(
            f"Mihomo asset SHA-256 mismatch: expected {expected_sha}, received {actual_sha}"
        )
    binary = _extract(archive, archive_format, key.startswith("windows-"))
    if not binary:
        raise CodecError("Mihomo archive contained an empty binary")
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(binary)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, os.stat(temporary).st_mode | stat.S_IXUSR)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target
