"""Cryptographic hash calculation for analyzed binaries."""

from __future__ import annotations

import hashlib

from binarylens.models import Hashes

_CHUNK_SIZE = 1024 * 1024  # 1 MB


def compute_hashes(filepath: str) -> Hashes:
    """Stream the file once and compute MD5, SHA-1, and SHA-256 together."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return Hashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())
