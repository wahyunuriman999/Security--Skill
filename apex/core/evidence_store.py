"""Local content-addressed evidence object store.

Only caller-attested redacted bytes are accepted. Objects are immutable and
verified by SHA-256 on every read. This is a local storage primitive, not a
secure enclave; the configured root directory must be owned by the APEX user.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class EvidenceObjectError(ValueError):
    pass


@dataclass(frozen=True)
class StoredEvidence:
    sha256: str
    byte_size: int
    storage_ref: str


class LocalEvidenceStore:
    def __init__(self, root: str | Path, *, max_bytes: int = _DEFAULT_MAX_BYTES):
        if type(max_bytes) is not int or not 1 <= max_bytes <= 100 * 1024 * 1024:
            raise EvidenceObjectError("max_bytes must be between 1 and 100 MiB")
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.is_dir():
            raise EvidenceObjectError("evidence root must be a real directory")
        try:
            self.root.chmod(0o700)
        except OSError:
            pass

    def _path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise EvidenceObjectError("invalid_sha256")
        directory = self.root / digest[:2]
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise EvidenceObjectError("evidence shard must be a real directory")
        return directory / digest

    @staticmethod
    def _hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def put(self, data: bytes, *, redacted: bool) -> StoredEvidence:
        if not isinstance(data, bytes):
            raise EvidenceObjectError("evidence data must be bytes")
        if redacted is not True:
            raise EvidenceObjectError("evidence_must_be_redacted_before_storage")
        if not data:
            raise EvidenceObjectError("empty_evidence_not_allowed")
        if len(data) > self.max_bytes:
            raise EvidenceObjectError("evidence_exceeds_configured_size_limit")

        digest = self._hash(data)
        destination = self._path(digest)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                raise EvidenceObjectError("existing_evidence_object_is_not_a_regular_file")
            if self.get(digest) != data:
                raise EvidenceObjectError("existing_evidence_object_integrity_failure")
            return StoredEvidence(digest, len(data), f"local://sha256/{digest}")

        fd, temporary_name = tempfile.mkstemp(prefix=".apex-evidence-", dir=destination.parent)
        temporary = Path(temporary_name)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if destination.is_symlink() or self.get(digest) != data:
                    raise EvidenceObjectError("evidence_object_collision_or_tampering")
            if os.name == "posix":
                destination.chmod(0o600)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return StoredEvidence(digest, len(data), f"local://sha256/{digest}")

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        if path.is_symlink() or not path.is_file():
            raise EvidenceObjectError("evidence_object_not_found_or_not_regular")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb", closefd=True) as stream:
                data = stream.read(self.max_bytes + 1)
        except OSError as exc:
            raise EvidenceObjectError("cannot_read_evidence_object") from exc
        if len(data) > self.max_bytes or self._hash(data) != digest:
            raise EvidenceObjectError("evidence_object_integrity_failure")
        return data

    def verify(self, digest: str) -> bool:
        self.get(digest)
        return True
