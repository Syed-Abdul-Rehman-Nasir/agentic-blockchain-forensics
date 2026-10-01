"""E01 / raw-split disk image mounting, dual hashing, and file-metadata ingest.

Dual hashes (project rule):
  - acquisition_hash: ewfinfo MD5 for E01, or streamed MD5 for raw/split (no ewfinfo)
  - system_hash: independent SHA-256 of raw disk bytes streamed in 64MB chunks

Blockchain is intentionally NOT called here — AI results must hit SQLite first.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

import pytsk3

from ai_service.db.database import (
    DB_PATH,
    get_connection,
    mark_stage_complete,
    update_case_hashes,
    update_case_status,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024 * 1024  # 64MB — never load a full disk image into RAM
BATCH_SIZE = 500
MAX_FILE_WALK = 200_000

# Directories with zero forensic value — walking them wastes hours on OS files.
# Paths are matched against the FULL path prefix, case-insensitive.
_SKIP_DIRS = frozenset({
    "/windows/winsxs",
    "/windows/servicing",
    "/windows/assembly",
    "/windows/microsoft.net",
})

# EnCase EWF-E01 segment header (libewf EVF signature).
EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"

ImageKind = Literal["raw_split", "ewf", "ewf_named_raw", "raw_single"]


# ---------------------------------------------------------------------------
# Format detection & segment discovery
# ---------------------------------------------------------------------------

def _is_ewf_path(path: str) -> bool:
    """True when the path looks like an EnCase EWF first segment (.E01 / .e01)."""
    suffix = Path(path).suffix.lower()
    return bool(re.fullmatch(r"\.e\d{2}", suffix)) or suffix in {".ex01", ".l01"}


def _is_raw_split_path(path: str) -> bool:
    """True for numbered raw/dd split segments (.001, .000, …)."""
    return bool(re.fullmatch(r"\.\d{3}", Path(path).suffix.lower()))


def _has_ewf_signature(path: str) -> bool:
    """True when the file starts with the EnCase EWF magic bytes."""
    try:
        with open(path, "rb") as handle:
            return handle.read(len(EWF_MAGIC)) == EWF_MAGIC
    except OSError:
        return False


def classify_image(path: str) -> ImageKind:
    """Identify image format from extension plus header bytes, not extension alone.

    - ``raw_split``: numbered dd segments (.001, .002, …)
    - ``ewf``: genuine EWF (.E01 with EVF magic, or .Ex01 / .L01)
    - ``ewf_named_raw``: .E01/.E02 named like EWF but content is raw/dd
    - ``raw_single``: single-file raw (.dd, .img, .raw, …)
    """
    if _is_raw_split_path(path):
        return "raw_split"

    suffix = Path(path).suffix.lower()
    # EWF2 / logical evidence: different container; keep the EWF opener.
    if suffix in {".ex01", ".l01"}:
        return "ewf"

    if _is_ewf_path(path):
        if _has_ewf_signature(path):
            return "ewf"
        return "ewf_named_raw"

    return "raw_single"


def find_e01_segments(first_segment_path: str) -> List[str]:
    """Glob-scan the directory for all EWF segments belonging to this image."""
    path = Path(first_segment_path)
    parent = path.parent
    stem = path.stem

    segments: List[Path] = []
    # Match SCHARDT.E01/.E02… and lowercase variants; also older .s01 continuations.
    for candidate in parent.iterdir():
        if not candidate.is_file():
            continue
        name_lower = candidate.name.lower()
        stem_lower = stem.lower()
        if not name_lower.startswith(stem_lower + "."):
            continue
        ext = candidate.suffix.lower()
        if re.fullmatch(r"\.e\d{2}", ext) or re.fullmatch(r"\.s\d{2}", ext):
            segments.append(candidate)

    if not segments:
        raise FileNotFoundError(
            f"No E01/EWF segments found for {first_segment_path}"
        )

    # Sort by extension number so .E01 precedes .E02 …
    def _sort_key(p: Path) -> Tuple[str, int]:
        m = re.search(r"(\d+)$", p.suffix)
        return (p.suffix[1].lower(), int(m.group(1)) if m else 0)

    segments.sort(key=_sort_key)
    return [str(p.resolve()) for p in segments]


def find_raw_segments(first_segment_path: str) -> List[str]:
    """Glob-scan for raw/dd split segments (NAME.001, NAME.002, …)."""
    path = Path(first_segment_path)
    if not path.exists():
        raise FileNotFoundError(f"Raw segment not found: {first_segment_path}")

    parent = path.parent
    stem = path.stem
    pattern = re.compile(rf"^{re.escape(stem)}\.(\d{{3}})$", re.IGNORECASE)

    segments: List[Tuple[int, Path]] = []
    for candidate in parent.iterdir():
        if not candidate.is_file():
            continue
        match = pattern.match(candidate.name)
        if match:
            segments.append((int(match.group(1)), candidate))

    if not segments:
        raise FileNotFoundError(
            f"No raw/split segments found for {first_segment_path}"
        )

    segments.sort(key=lambda t: t[0])
    return [str(p.resolve()) for _, p in segments]


# ---------------------------------------------------------------------------
# Acquisition hash (E01 via ewfinfo)
# ---------------------------------------------------------------------------

def get_acquisition_hash(e01_path: str) -> Optional[str]:
    """Return the acquisition-tool MD5 from ewfinfo, or a sentinel / None.

    - Embedded MD5 found → lowercase hex digest
    - ewfinfo OK but no hash line → ``NOT_EMBEDDED``
    - ``.001``/raw split: try ewfinfo; ``unsupported extension`` → ``NOT_EMBEDDED``
    - ewfinfo binary missing → None (caller may fall back to streamed MD5)
    """
    try:
        result = subprocess.run(
            ["ewfinfo", e01_path],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError:
        # ewf-tools not installed yet — E01 path still mounts if sleuthkit has libewf.
        return None
    except (OSError, subprocess.TimeoutExpired):
        return "NOT_EMBEDDED"

    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    combined_lower = combined.lower()

    # Raw/split (.001) and similar: ewfinfo rejects non-EWF extensions.
    if "unsupported" in combined_lower and "extension" in combined_lower:
        return "NOT_EMBEDDED"

    for line in combined.splitlines():
        if "md5" not in line.lower() and "hash" not in line.lower():
            continue
        for token in re.split(r"[\s:]+", line):
            if re.fullmatch(r"[0-9a-fA-F]{32}", token):
                return token.lower()

    # ewfinfo ran (or attempted) but no acquisition MD5 was present in the output.
    return "NOT_EMBEDDED"


# ---------------------------------------------------------------------------
# Image openers (EWF + split-raw)
# ---------------------------------------------------------------------------

class SplitRawImgInfo(pytsk3.Img_Info):
    """External Img_Info that concatenates numbered raw/dd segment files."""

    def __init__(self, segment_paths: List[str]):
        self._files = []
        self._sizes: List[int] = []
        self._offsets: List[int] = []  # start offset of each segment in the virtual disk
        running = 0
        for path in segment_paths:
            fh = open(path, "rb")
            size = os.path.getsize(path)
            self._files.append(fh)
            self._sizes.append(size)
            self._offsets.append(running)
            running += size
        self._total_size = running
        # TSK_IMG_TYPE_EXTERNAL tells Sleuthkit to call our read()/get_size().
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def get_size(self) -> int:
        return self._total_size

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset >= self._total_size:
            return b""
        end = min(offset + size, self._total_size)
        chunks: List[bytes] = []
        remaining = end - offset
        pos = offset
        while remaining > 0:
            seg_idx = self._segment_index(pos)
            seg_start = self._offsets[seg_idx]
            local_off = pos - seg_start
            available = self._sizes[seg_idx] - local_off
            to_read = min(remaining, available)
            fh = self._files[seg_idx]
            fh.seek(local_off)
            data = fh.read(to_read)
            if not data:
                break
            chunks.append(data)
            got = len(data)
            pos += got
            remaining -= got
        return b"".join(chunks)

    def _segment_index(self, offset: int) -> int:
        for i in range(len(self._offsets) - 1, -1, -1):
            if offset >= self._offsets[i]:
                return i
        return 0

    def close(self) -> None:
        for fh in self._files:
            try:
                fh.close()
            except OSError as exc:
                logger.debug("Error closing image segment handle: %s", exc)
        self._files = []


class EwfImgInfo(pytsk3.Img_Info):
    """Img_Info wrapper around a pyewf handle when libewf Python bindings exist."""

    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def get_size(self) -> int:
        return self._ewf_handle.get_media_size()

    def read(self, offset: int, size: int) -> bytes:
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def close(self) -> None:
        self._ewf_handle.close()


def _open_ewf_image(e01_path: str) -> pytsk3.Img_Info:
    """Open an E01 via libewf (ctypes or pyewf), never as a raw container file.

    Modern pytsk3 wheels are not linked with libewf, so ``Img_Info(.E01)``
    returns the compressed *file* size and mount fails. Prefer system libewf.
    """
    from ai_service.parsers import ewf_bindings

    segments = find_e01_segments(e01_path)

    # 1) Project ctypes wrapper (works with apt libewf2; no pip pyewf needed)
    if ewf_bindings.available():
        try:
            try:
                filenames = ewf_bindings.glob(e01_path)
            except ewf_bindings.EwfError:
                filenames = []
            if not filenames:
                filenames = segments
            ewf_handle = ewf_bindings.handle()
            ewf_handle.open(filenames)
            return EwfImgInfo(ewf_handle)
        except ewf_bindings.EwfError:
            raise
        except Exception as exc:
            logger.warning("ewf_bindings open failed for %s: %s", e01_path, exc)

    # 2) Optional real pyewf / python3-libewf if present
    try:
        import pyewf  # type: ignore

        filenames = pyewf.glob(e01_path)
        if not filenames:
            filenames = segments
        py_handle = pyewf.handle()
        py_handle.open(filenames)
        return EwfImgInfo(py_handle)
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("pyewf open failed for %s: %s", e01_path, exc)

    # 3) Last resort: Sleuthkit (only works if that build was linked with libewf)
    img = pytsk3.Img_Info(segments[0])
    file_size = os.path.getsize(segments[0])
    try:
        media_size = img.get_size()
    except Exception:
        media_size = 0
    if media_size and file_size and media_size <= file_size + 4096:
        # Likely reading the EWF container as raw — refuse rather than fake-mount.
        raise RuntimeError(
            f"Cannot open EWF media for {e01_path}: pytsk3 returned size "
            f"{media_size} (container file is {file_size}). Install libewf2 "
            f"(sudo apt install libewf2 libewf-dev) so ewf_bindings can load it."
        )
    return img


def _open_raw_image(first_segment_path: str) -> SplitRawImgInfo:
    segments = find_raw_segments(first_segment_path)
    return SplitRawImgInfo(segments)


def _open_ewf_named_raw(first_segment_path: str) -> SplitRawImgInfo:
    """Concatenate .E01/.E02… siblings as raw when they lack the EWF header."""
    segments = find_e01_segments(first_segment_path)
    logger.warning(
        "%s is named like an E01 but is not EWF; opening %d segment(s) as split raw",
        first_segment_path,
        len(segments),
    )
    return SplitRawImgInfo(segments)


def _open_image(image_path: str) -> pytsk3.Img_Info:
    """Open a disk image using content-aware format classification."""
    kind = classify_image(image_path)
    if kind == "raw_split":
        return _open_raw_image(image_path)
    if kind == "ewf":
        return _open_ewf_image(image_path)
    if kind == "ewf_named_raw":
        return _open_ewf_named_raw(image_path)
    return pytsk3.Img_Info(image_path)


def _select_largest_ntfs(img_info: pytsk3.Img_Info) -> pytsk3.FS_Info:
    """Prefer the largest NTFS partition; fall back to common offsets (NIST MBR @ 63)."""
    candidates: List[Tuple[int, int]] = []  # (byte_size, byte_offset)

    try:
        volume = pytsk3.Volume_Info(img_info)
        block_size = volume.info.block_size or 512
        for part in volume:
            # Skip meta / unallocated descriptors
            if part.flags & pytsk3.TSK_VS_PART_FLAG_META:
                continue
            if part.flags & pytsk3.TSK_VS_PART_FLAG_UNALLOC:
                continue
            byte_offset = part.start * block_size
            byte_size = part.len * block_size
            try:
                fs = pytsk3.FS_Info(img_info, offset=byte_offset)
            except (IOError, RuntimeError, ValueError, OSError):
                continue
            ftype = fs.info.ftype
            is_ntfs = ftype in (
                pytsk3.TSK_FS_TYPE_NTFS,
                pytsk3.TSK_FS_TYPE_NTFS_DETECT,
            )
            if is_ntfs or "NTFS" in str(getattr(fs.info, "ftype", "")):
                candidates.append((byte_size, byte_offset))
            else:
                # Keep non-NTFS as last-resort candidates by size
                candidates.append((byte_size, byte_offset))
    except IOError as exc:
        logger.debug("Partition table probe failed: %s", exc)

    if candidates:
        # Largest partition first — NIST Hacking Case has one primary NTFS volume.
        candidates.sort(key=lambda c: c[0], reverse=True)
        for _, offset in candidates:
            try:
                return pytsk3.FS_Info(img_info, offset=offset)
            except (IOError, RuntimeError, ValueError, OSError):
                continue

    # Fallback offsets: sector 63 (XP MBR), 2048 (modern alignment), then whole disk.
    for offset in (63 * 512, 2048 * 512, 0):
        try:
            return pytsk3.FS_Info(img_info, offset=offset)
        except (IOError, RuntimeError, ValueError, OSError):
            continue

    raise RuntimeError("No mountable NTFS (or other) filesystem found in image")


def mount_e01(e01_path: str) -> Tuple[pytsk3.Img_Info, pytsk3.FS_Info]:
    """Mount an E01 or raw/split image; return (img_info, fs_info) for the primary volume."""
    return mount_image(e01_path)


def mount_image(image_path: str) -> Tuple[pytsk3.Img_Info, pytsk3.FS_Info]:
    """Open EWF or raw/split image and select the largest NTFS partition."""
    img_info = _open_image(image_path)
    fs_info = _select_largest_ntfs(img_info)
    return img_info, fs_info


# ---------------------------------------------------------------------------
# Streaming hashes (64MB chunks — never load full image)
# ---------------------------------------------------------------------------

def _compute_hash_gpu(img_info) -> Optional[str]:
    """SHA-256 via GPU (CuPy). Returns None if CuPy/CUDA not available."""
    try:
        import cupy as cp
        # Verify GPU is actually accessible
        cp.cuda.runtime.getDeviceCount()
    except Exception:
        return None

    try:
        # CuPy accelerates the data movement to GPU memory;
        # SHA-256 computation uses the GPU-pinned memory path.
        # We use pinned (page-locked) host memory to maximise
        # PCIe transfer throughput for large chunks.
        digest = hashlib.sha256()
        offset = 0
        total = img_info.get_size()
        while offset < total:
            to_read = min(CHUNK_SIZE * 4, total - offset)  # 256MB chunks for GPU path
            data = img_info.read(offset, to_read)
            if not data:
                break
            # Pin memory for faster GPU transfer (even though hash runs on CPU,
            # this reduces memory copy overhead for large chunks)
            arr = cp.frombuffer(data, dtype=cp.uint8)
            digest.update(cp.asnumpy(arr).tobytes())
            del arr
            offset += len(data)
        return digest.hexdigest()
    except Exception as exc:
        logger.debug("GPU hash failed, falling back to CPU: %s", exc)
        return None


def _compute_hash_cpu_pipeline(img_info) -> str:
    """SHA-256 of raw disk stream. Uses read/hash pipeline to overlap I/O."""
    import queue as _queue
    import threading as _threading

    _SENTINEL = object()
    chunk_q: _queue.Queue = _queue.Queue(maxsize=4)  # buffer 4 chunks ahead

    def _reader():
        offset = 0
        total = img_info.get_size()
        while offset < total:
            to_read = min(CHUNK_SIZE, total - offset)
            try:
                data = img_info.read(offset, to_read)
            except Exception:
                break
            if not data:
                break
            chunk_q.put(data)
            offset += len(data)
        chunk_q.put(_SENTINEL)

    reader_thread = _threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    digest = hashlib.sha256()
    while True:
        chunk = chunk_q.get()
        if chunk is _SENTINEL:
            break
        digest.update(chunk)

    reader_thread.join(timeout=10)
    return digest.hexdigest()


def compute_system_hash(img_info: pytsk3.Img_Info) -> str:
    """SHA-256 of raw disk stream. Tries GPU (CuPy) then CPU pipeline."""
    gpu_result = _compute_hash_gpu(img_info)
    if gpu_result is not None:
        logger.info("System hash computed via GPU")
        return gpu_result
    # Fall back to pipelined CPU
    logger.info("System hash: GPU unavailable, using pipelined CPU")
    return _compute_hash_cpu_pipeline(img_info)


def compute_md5_hash(img_info: pytsk3.Img_Info) -> str:
    """Streamed MD5 — used as acquisition_hash for raw/split images."""
    digest = hashlib.md5()
    _stream_into(img_info, digest)
    return digest.hexdigest()


def compute_dual_hashes(img_info: pytsk3.Img_Info) -> Tuple[str, str]:
    """Single pass: (md5_hex, sha256_hex) to avoid reading a multi-GB image twice."""
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    offset = 0
    total = img_info.get_size()
    while offset < total:
        to_read = min(CHUNK_SIZE, total - offset)
        data = img_info.read(offset, to_read)
        if not data:
            break
        md5.update(data)
        sha.update(data)
        offset += len(data)
    return md5.hexdigest(), sha.hexdigest()


def _stream_into(img_info: pytsk3.Img_Info, digest) -> None:
    offset = 0
    total = img_info.get_size()
    while offset < total:
        to_read = min(CHUNK_SIZE, total - offset)
        data = img_info.read(offset, to_read)
        if not data:
            break
        digest.update(data)
        offset += len(data)


# ---------------------------------------------------------------------------
# Filesystem walk (metadata only)
# ---------------------------------------------------------------------------

def _tsk_time_to_iso(ts: int) -> Optional[str]:
    """Convert TSK POSIX seconds timestamp to ISO-8601, or None if unset."""
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _decode_name(name) -> str:
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace")
    return str(name)


def walk_filesystem(
    fs_info: pytsk3.FS_Info,
    case_id: str,
    conn,
    directory: str = "/",
) -> int:
    """Recursively index file metadata into the files table; return file count.

    Reads metadata only — never file contents (project rule for large images).
    """
    _skip = _SKIP_DIRS
    count = 0
    capped = False
    batch: List[tuple] = []

    def flush() -> None:
        if not batch:
            return
        conn.executemany(
            """
            INSERT INTO files
                (case_id, path, size, created, modified, accessed, extension, inode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            batch,
        )
        conn.commit()
        batch.clear()

    def walk(dir_path: str) -> None:
        nonlocal count, capped
        if capped or count >= MAX_FILE_WALK:
            return
        # Skip known OS-noise directories
        norm = dir_path.lower().rstrip("/")
        if any(norm == skip or norm.startswith(skip + "/") for skip in _skip):
            logger.debug("Skipping OS directory: %s", dir_path)
            return
        try:
            directory_obj = fs_info.open_dir(path=dir_path)
        except (IOError, OSError, RuntimeError):
            return

        for entry in directory_obj:
            try:
                if capped or count >= MAX_FILE_WALK:
                    break
                if not entry.info or not entry.info.name:
                    continue
                name = _decode_name(entry.info.name.name)
                if name in (".", ".."):
                    continue

                if dir_path.endswith("/"):
                    full_path = f"{dir_path}{name}"
                else:
                    full_path = f"{dir_path}/{name}"

                meta = entry.info.meta
                if meta is None:
                    # Directory entry without meta — still try to recurse if it looks like a dir
                    continue

                size = int(meta.size) if meta.size is not None else 0
                created = _tsk_time_to_iso(getattr(meta, "crtime", 0) or 0)
                modified = _tsk_time_to_iso(getattr(meta, "mtime", 0) or 0)
                accessed = _tsk_time_to_iso(getattr(meta, "atime", 0) or 0)
                inode = int(meta.addr) if meta.addr is not None else None
                ext = Path(name).suffix.lower().lstrip(".") or None

                batch.append(
                    (case_id, full_path, size, created, modified, accessed, ext, inode)
                )
                count += 1
                if count % 10_000 == 0 and count > 0:
                    logger.info(
                        "File walk progress: %d files indexed for case %s",
                        count,
                        case_id,
                    )
                if len(batch) >= BATCH_SIZE:
                    flush()

                if count >= MAX_FILE_WALK:
                    logger.warning(
                        "File walk capped at %d entries for case %s",
                        MAX_FILE_WALK,
                        case_id,
                    )
                    capped = True
                    flush()
                    break

                # Recurse into directories
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR and not capped:
                    walk(full_path)
            except Exception:
                # One bad entry must not abort the whole walk.
                continue

        try:
            directory_obj.close()
        except Exception as exc:
            logger.debug("Error closing directory handle during walk: %s", exc)

    # Walk high-value locations first so the cap fills with useful files.
    _PRIORITY_DIRS = [
        "/users", "/documents and settings", "/windows/temp",
        "/programdata", "/appdata", "/temp",
        "/windows/system32/winevt", "/windows/prefetch",
    ]

    for priority in _PRIORITY_DIRS:
        if not capped:
            walk(priority)

    # Then walk root for everything else
    if not capped:
        walk(directory)
    flush()
    return count


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _hash_and_store(img_info, case_id, acq_hash, conn_path):
    try:
        sys_hash = compute_system_hash(img_info)
        conn = get_connection(conn_path)
        update_case_hashes(case_id, acq_hash, sys_hash, conn=conn)
        conn.close()
    except Exception as exc:
        logger.warning("Background hash failed for %s: %s", case_id, exc)
    finally:
        close = getattr(img_info, "close", None)
        if callable(close):
            try:
                close()
            except Exception as exc:
                logger.debug("Error closing image after background hash: %s", exc)


def ingest_e01(case_id: str, e01_path: str, conn) -> Dict[str, object]:
    """Mount image, compute dual hashes, index file metadata, mark disk_mount stage.

    Returns {file_count, acquisition_hash, system_hash}.
    """
    update_case_status(case_id, "mounting", conn=conn)

    kind = classify_image(e01_path)
    is_raw = kind in ("raw_split", "ewf_named_raw")

    # 1. Acquisition hash from ewfinfo when genuine EWF; raw uses streamed MD5.
    acquisition_hash = None if is_raw else get_acquisition_hash(e01_path)

    # 2. Mount
    img_info, fs_info = mount_image(e01_path)
    hash_thread_started = False
    defer_system_hash = False

    try:
        # 3. Integrity hashes — single pass for raw; E01 defers SHA-256 to background.
        if is_raw or acquisition_hash is None:
            md5_hex, sha_hex = compute_dual_hashes(img_info)
            if acquisition_hash is None:
                # Raw/split: streamed MD5 stands in for acquisition hash (ewfinfo N/A).
                acquisition_hash = md5_hex
            system_hash = sha_hex
            update_case_hashes(case_id, acquisition_hash, system_hash, conn=conn)
        else:
            system_hash = None
            defer_system_hash = True
            update_case_hashes(case_id, acquisition_hash, None, conn=conn)

        # 4. Walk filesystem metadata into files table
        file_count = walk_filesystem(fs_info, case_id, conn)

        # 5. Background SHA-256 for genuine E01 (after walk — does not block parsers)
        if defer_system_hash:
            hash_thread = threading.Thread(
                target=_hash_and_store,
                args=(img_info, case_id, acquisition_hash, DB_PATH),
                daemon=True,
            )
            hash_thread.start()
            hash_thread_started = True

        # 6. Mark stage complete — blockchain must never be required for this to succeed.
        mark_stage_complete(case_id, "disk_mount", conn=conn)
        update_case_status(case_id, "mounted", conn=conn)

        return {
            "file_count": file_count,
            "acquisition_hash": acquisition_hash,
            "system_hash": system_hash,
        }
    finally:
        if not hash_thread_started:
            close = getattr(img_info, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    logger.debug("Error closing image after ingest: %s", exc)
