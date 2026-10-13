"""Tests for ai_service.parsers.disk_mount.

Header/classification tests use tiny temp files. Hashing and full ingest
against the NIST SCHARDT image stream ~3.1 GB — those are marked slow.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

import ai_service.db.database as database
from ai_service.db.database import create_case, get_connection, initialise_db
from ai_service.parsers.disk_mount import (
    EWF_MAGIC,
    SplitRawImgInfo,
    _compute_hash_cpu_pipeline,
    _has_ewf_signature,
    _open_image,
    classify_image,
    compute_dual_hashes,
    find_raw_segments,
    get_acquisition_hash,
    ingest_e01,
    mount_e01,
)
from ai_service.parsers.extract_utils import extract_file

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NIST_IMAGE = PROJECT_ROOT / "data" / "test_images" / "SCHARDT.001"
SCHARDT_E01 = PROJECT_ROOT / "data" / "test_images" / "SCHARDT.E01"

requires_nist = pytest.mark.skipif(
    not NIST_IMAGE.exists(),
    reason=f"NIST image not found at {NIST_IMAGE}",
)


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    db_file = tmp_path / "mount_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    monkeypatch.setenv("FORENSIC_DB_PATH", str(db_file))
    initialise_db()
    conn = get_connection()
    yield conn
    conn.close()


def test_has_ewf_signature_detects_evf_magic(tmp_path):
    path = tmp_path / "sample.E01"
    path.write_bytes(EWF_MAGIC + b"\x00" * 16)
    assert _has_ewf_signature(str(path)) is True


def test_has_ewf_signature_rejects_raw_mbr_header(tmp_path):
    path = tmp_path / "sample.E01"
    path.write_bytes(b"\x33\xc0\x8e\xd0" + b"\x00" * 16)
    assert _has_ewf_signature(str(path)) is False


def test_classify_numbered_raw_split(tmp_path):
    path = tmp_path / "DISK.001"
    path.write_bytes(b"\x00" * 8)
    assert classify_image(str(path)) == "raw_split"


def test_classify_genuine_e01_as_ewf(tmp_path):
    path = tmp_path / "DISK.E01"
    path.write_bytes(EWF_MAGIC + b"\x00" * 8)
    assert classify_image(str(path)) == "ewf"


def test_classify_mislabeled_e01_as_ewf_named_raw(tmp_path):
    path = tmp_path / "DISK.E01"
    path.write_bytes(b"\x33\xc0\x8e\xd0" + b"\x00" * 8)
    assert classify_image(str(path)) == "ewf_named_raw"


def test_classify_ex01_stays_ewf_even_without_evf_magic(tmp_path):
    path = tmp_path / "DISK.Ex01"
    path.write_bytes(b"\x00" * 16)
    assert classify_image(str(path)) == "ewf"


def test_classify_single_raw_dd(tmp_path):
    path = tmp_path / "DISK.dd"
    path.write_bytes(b"\x00" * 8)
    assert classify_image(str(path)) == "raw_single"


def test_open_mislabeled_e01_concatenates_raw_segments(tmp_path):
    first = tmp_path / "DISK.E01"
    second = tmp_path / "DISK.E02"
    first.write_bytes(b"AAAA")
    second.write_bytes(b"BBBB")

    img = _open_image(str(first))
    try:
        assert isinstance(img, SplitRawImgInfo)
        assert img.get_size() == 8
        assert img.read(0, 8) == b"AAAABBBB"
    finally:
        img.close()


def test_split_raw_img_info_closes_handles_on_partial_init_failure(tmp_path):
    """A missing later segment must not leave earlier segment files open."""
    first = tmp_path / "DISK.001"
    first.write_bytes(b"AAAA")
    missing = tmp_path / "DISK.002"

    with pytest.raises(OSError):
        SplitRawImgInfo([str(first), str(missing)])

    # First segment must remain readable (no leaked exclusive handle).
    assert first.read_bytes() == b"AAAA"


def test_split_raw_img_info_close_is_idempotent(tmp_path):
    first = tmp_path / "DISK.001"
    first.write_bytes(b"ABCD")
    img = SplitRawImgInfo([str(first)])
    img.close()
    img.close()
    assert img._files == []


def test_extract_file_closes_pytsk_handle(tmp_path):
    """extract_file must always close the pytsk3 file handle, even on success."""

    class _Meta:
        size = 4

    class _Info:
        meta = _Meta()

    class _File:
        def __init__(self):
            self.info = _Info()
            self.closed = False

        def read_random(self, offset: int, size: int) -> bytes:
            return b"DATA"[offset : offset + size]

        def close(self) -> None:
            self.closed = True

    opened = _File()

    class _FS:
        def open(self, _path: str):
            return opened

    out = tmp_path / "artifact.bin"
    written = extract_file(_FS(), "/Windows/System32/config/SYSTEM", str(out))
    assert written == 4
    assert out.read_bytes() == b"DATA"
    assert opened.closed is True


class _PartialImg:
    """Fake image that advertises more bytes than it can deliver."""

    def __init__(self, payload: bytes, claimed_size: int):
        self._payload = payload
        self._claimed = claimed_size

    def get_size(self) -> int:
        return self._claimed

    def read(self, offset: int, size: int) -> bytes:
        if offset >= len(self._payload):
            return b""
        return self._payload[offset : offset + size]


def test_compute_dual_hashes_rejects_incomplete_stream():
    img = _PartialImg(b"ABCD", claimed_size=16)
    with pytest.raises(RuntimeError, match="incomplete image stream"):
        compute_dual_hashes(img)


def test_compute_hash_cpu_pipeline_rejects_incomplete_stream():
    img = _PartialImg(b"ABCD", claimed_size=32)
    with pytest.raises(RuntimeError, match="incomplete image stream"):
        _compute_hash_cpu_pipeline(img)


def test_compute_dual_hashes_accepts_complete_stream():
    payload = b"complete-hash-payload"
    img = _PartialImg(payload, claimed_size=len(payload))
    md5_hex, sha_hex = compute_dual_hashes(img)
    assert md5_hex == hashlib.md5(payload).hexdigest()
    assert sha_hex == hashlib.sha256(payload).hexdigest()


def test_ingest_ewf_named_raw_streams_md5_not_ewfinfo(tmp_path, temp_db, monkeypatch):
    """Misnamed .E01 must skip ewfinfo and store streamed MD5 + SHA-256."""
    e01 = tmp_path / "CASE.E01"
    e01.write_bytes(b"\x33\xc0" + b"\x00" * 32)

    payload = b"abcd"

    class FakeImg:
        def get_size(self) -> int:
            return len(payload)

        def read(self, offset: int, size: int) -> bytes:
            return payload[offset : offset + size]

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "ai_service.parsers.disk_mount.mount_image",
        lambda _path: (FakeImg(), object()),
    )
    monkeypatch.setattr(
        "ai_service.parsers.disk_mount.walk_filesystem",
        lambda *_args, **_kwargs: 0,
    )

    def _ewfinfo_must_not_run(_path: str):
        pytest.fail("ewfinfo must not run for misnamed raw E01")

    monkeypatch.setattr(
        "ai_service.parsers.disk_mount.get_acquisition_hash",
        _ewfinfo_must_not_run,
    )

    create_case("TEST_MISNAMED", "Misnamed E01", str(e01), conn=temp_db)
    result = ingest_e01("TEST_MISNAMED", str(e01), temp_db)

    assert result["acquisition_hash"] == hashlib.md5(payload).hexdigest()
    assert result["system_hash"] == hashlib.sha256(payload).hexdigest()


@pytest.mark.skipif(not SCHARDT_E01.exists(), reason="SCHARDT.E01 missing")
def test_schardt_e01_classifies_as_ewf_named_raw():
    assert classify_image(str(SCHARDT_E01)) == "ewf_named_raw"


@requires_nist
def test_find_raw_segments_returns_all_five():
    segments = find_raw_segments(str(NIST_IMAGE))
    assert len(segments) == 5
    assert all(Path(s).exists() for s in segments)
    assert segments[0].endswith("SCHARDT.001")
    assert segments[-1].endswith("SCHARDT.005")


@requires_nist
def test_get_acquisition_hash_raw_returns_none():
    # ewfinfo does not apply to raw/split — ingest uses streamed MD5 instead.
    assert get_acquisition_hash(str(NIST_IMAGE)) is None


@requires_nist
def test_mount_e01_returns_valid_img_and_fs():
    img_info, fs_info = mount_e01(str(NIST_IMAGE))
    try:
        assert img_info.get_size() > 0
        # NIST Hacking Case is ~3.1 GB across five segments
        assert img_info.get_size() == 3331194880
        assert fs_info is not None
        root = fs_info.open_dir(path="/")
        names = []
        for entry in root:
            if entry.info and entry.info.name:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                if name not in (".", ".."):
                    names.append(name)
        assert (
            "Documents and Settings" in names
            or "WINDOWS" in names
            or "Windows" in names
        )
    finally:
        img_info.close()


@pytest.mark.slow
@requires_nist
def test_compute_system_hash_and_dual_hashes_differ():
    """Streamed SHA-256 is 64 hex chars; MD5 is 32; digests must differ."""
    img_info, _ = mount_e01(str(NIST_IMAGE))
    try:
        md5_hex, sha_hex = compute_dual_hashes(img_info)
        assert re.fullmatch(r"[0-9a-f]{32}", md5_hex)
        assert re.fullmatch(r"[0-9a-f]{64}", sha_hex)
        assert md5_hex != sha_hex
    finally:
        img_info.close()


@pytest.mark.slow
@requires_nist
def test_ingest_e01_walks_and_stores_dual_hashes(temp_db):
    """Full ingest: dual hashes + filesystem walk + disk_mount stage."""
    create_case("TEST_NIST", "NIST Hacking Case", str(NIST_IMAGE), conn=temp_db)
    result = ingest_e01("TEST_NIST", str(NIST_IMAGE), temp_db)

    # Plausible file count for NIST XP image
    assert result["file_count"] > 1000
    assert re.fullmatch(r"[0-9a-f]{32}", result["acquisition_hash"])
    assert re.fullmatch(r"[0-9a-f]{64}", result["system_hash"])
    assert result["acquisition_hash"] != result["system_hash"]

    case = temp_db.execute(
        "SELECT acquisition_hash, system_hash FROM cases WHERE case_id = ?",
        ("TEST_NIST",),
    ).fetchone()
    assert case["acquisition_hash"] == result["acquisition_hash"]
    assert case["system_hash"] == result["system_hash"]

    file_count = temp_db.execute(
        "SELECT COUNT(*) AS c FROM files WHERE case_id = ?",
        ("TEST_NIST",),
    ).fetchone()["c"]
    assert file_count == result["file_count"]

    stages = temp_db.execute(
        "SELECT stage_name FROM analysis_stages WHERE case_id = ?",
        ("TEST_NIST",),
    ).fetchall()
    assert any(s["stage_name"] == "disk_mount" for s in stages)
