import hashlib
import os
import tempfile

from binarylens.analysis.hashes import compute_hashes


def test_compute_hashes_matches_hashlib():
    content = b"BinaryLens test content" * 1000
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        path = f.name

    try:
        result = compute_hashes(path)
        assert result.md5 == hashlib.md5(content).hexdigest()
        assert result.sha1 == hashlib.sha1(content).hexdigest()
        assert result.sha256 == hashlib.sha256(content).hexdigest()
    finally:
        os.unlink(path)


def test_compute_hashes_empty_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        result = compute_hashes(path)
        assert result.md5 == hashlib.md5(b"").hexdigest()
        assert result.sha256 == hashlib.sha256(b"").hexdigest()
    finally:
        os.unlink(path)


def test_compute_hashes_large_file_chunking():
    # Larger than the internal 1MB chunk size to exercise the streaming loop.
    content = os.urandom(2 * 1024 * 1024 + 137)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        path = f.name

    try:
        result = compute_hashes(path)
        assert result.sha256 == hashlib.sha256(content).hexdigest()
    finally:
        os.unlink(path)
