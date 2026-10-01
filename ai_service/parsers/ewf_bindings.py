"""ctypes bindings for system libewf (Expert Witness / E01).

pip has no usable ``pyewf`` wheel for Python 3.11. Modern ``pytsk3`` wheels also
ship without libewf, so ``pytsk3.Img_Info(path.E01)`` reads the *container*
(compressed file size) instead of the logical media — and mount fails.

This module wraps the distro ``libewf.so`` (``libewf-dev`` / ``libewf2``) with a
small API compatible with what ``disk_mount._open_ewf_image`` expects from pyewf:

    filenames = ewf_bindings.glob(path)
    handle = ewf_bindings.handle()
    handle.open(filenames)
    handle.get_media_size() / seek() / read() / close()
"""

from __future__ import annotations

import ctypes
import logging
import os
from ctypes import (
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_int64,
    c_size_t,
    c_uint64,
    c_uint8,
    c_void_p,
    create_string_buffer,
)
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

LIBEWF_OPEN_READ = 0x01
LIBEWF_FORMAT_UNKNOWN = 0x00
SEEK_SET = 0

_lib: Optional[ctypes.CDLL] = None


class EwfError(RuntimeError):
    """Raised when a libewf call fails."""


def _load_lib() -> ctypes.CDLL:
    global _lib
    if _lib is not None:
        return _lib
    candidates = (
        "libewf.so.2",
        "libewf.so",
        "/usr/lib/x86_64-linux-gnu/libewf.so.2",
        "/usr/lib/x86_64-linux-gnu/libewf.so",
    )
    last_err: Optional[OSError] = None
    for name in candidates:
        try:
            _lib = ctypes.CDLL(name)
            break
        except OSError as exc:
            last_err = exc
            _lib = None
    if _lib is None:
        raise EwfError(
            "Cannot load libewf. Install: sudo apt install libewf2 libewf-dev. "
            f"Last error: {last_err}"
        )

    lib = _lib
    # Opaque pointers
    lib.libewf_handle_initialize.argtypes = [POINTER(c_void_p), POINTER(c_void_p)]
    lib.libewf_handle_initialize.restype = c_int
    lib.libewf_handle_free.argtypes = [POINTER(c_void_p), POINTER(c_void_p)]
    lib.libewf_handle_free.restype = c_int
    lib.libewf_handle_open.argtypes = [
        c_void_p,
        POINTER(c_char_p),
        c_int,
        c_int,
        POINTER(c_void_p),
    ]
    lib.libewf_handle_open.restype = c_int
    lib.libewf_handle_close.argtypes = [c_void_p, POINTER(c_void_p)]
    lib.libewf_handle_close.restype = c_int
    lib.libewf_handle_get_media_size.argtypes = [
        c_void_p,
        POINTER(c_uint64),
        POINTER(c_void_p),
    ]
    lib.libewf_handle_get_media_size.restype = c_int
    lib.libewf_handle_seek_offset.argtypes = [
        c_void_p,
        c_int64,
        c_int,
        POINTER(c_void_p),
    ]
    lib.libewf_handle_seek_offset.restype = c_int64
    lib.libewf_handle_read_buffer.argtypes = [
        c_void_p,
        c_void_p,
        c_size_t,
        POINTER(c_void_p),
    ]
    lib.libewf_handle_read_buffer.restype = c_int64  # ssize_t
    lib.libewf_glob.argtypes = [
        c_char_p,
        c_size_t,
        c_uint8,
        POINTER(POINTER(c_char_p)),
        POINTER(c_int),
        POINTER(c_void_p),
    ]
    lib.libewf_glob.restype = c_int
    lib.libewf_glob_free.argtypes = [POINTER(c_char_p), c_int, POINTER(c_void_p)]
    lib.libewf_glob_free.restype = c_int
    lib.libewf_error_free.argtypes = [POINTER(c_void_p)]
    lib.libewf_error_free.restype = None
    return lib


def available() -> bool:
    """True if system libewf can be loaded."""
    try:
        _load_lib()
        return True
    except EwfError:
        return False


def _raise_ewf(msg: str, error_ptr: c_void_p) -> None:
    lib = _load_lib()
    if error_ptr:
        lib.libewf_error_free(byref(error_ptr))
    raise EwfError(msg)


def glob(filename: str) -> List[str]:
    """Return EWF segment paths for *filename* (same idea as pyewf.glob)."""
    lib = _load_lib()
    path_b = os.fsencode(filename)
    filenames_ptr = POINTER(c_char_p)()
    count = c_int(0)
    error = c_void_p()
    rc = lib.libewf_glob(
        path_b,
        len(path_b),
        LIBEWF_FORMAT_UNKNOWN,
        byref(filenames_ptr),
        byref(count),
        byref(error),
    )
    if rc != 1:
        _raise_ewf(f"libewf_glob failed for {filename!r}", error)

    out: List[str] = []
    try:
        for i in range(count.value):
            out.append(os.fsdecode(filenames_ptr[i]))
    finally:
        err2 = c_void_p()
        lib.libewf_glob_free(filenames_ptr, count, byref(err2))
        if err2:
            lib.libewf_error_free(byref(err2))
    return out


class Handle:
    """pyewf.handle()-compatible wrapper around libewf_handle_t."""

    def __init__(self) -> None:
        self._lib = _load_lib()
        self._handle = c_void_p()
        error = c_void_p()
        if self._lib.libewf_handle_initialize(byref(self._handle), byref(error)) != 1:
            _raise_ewf("libewf_handle_initialize failed", error)
        self._opened = False

    def open(self, filenames: Sequence[str]) -> None:
        if not filenames:
            raise EwfError("open() requires at least one EWF segment path")
        # Keep byte strings alive for the C call
        encoded = [os.fsencode(p) for p in filenames]
        arr = (c_char_p * len(encoded))(*encoded)
        error = c_void_p()
        rc = self._lib.libewf_handle_open(
            self._handle,
            ctypes.cast(arr, POINTER(c_char_p)),
            len(encoded),
            LIBEWF_OPEN_READ,
            byref(error),
        )
        if rc != 1:
            _raise_ewf(f"libewf_handle_open failed for {list(filenames)!r}", error)
        self._opened = True

    def get_media_size(self) -> int:
        size = c_uint64(0)
        error = c_void_p()
        if self._lib.libewf_handle_get_media_size(self._handle, byref(size), byref(error)) != 1:
            _raise_ewf("libewf_handle_get_media_size failed", error)
        return int(size.value)

    def seek(self, offset: int, whence: int = SEEK_SET) -> int:
        error = c_void_p()
        pos = self._lib.libewf_handle_seek_offset(
            self._handle, c_int64(offset), c_int(whence), byref(error)
        )
        if pos < 0:
            _raise_ewf(f"libewf_handle_seek_offset({offset}) failed", error)
        return int(pos)

    def read(self, size: int) -> bytes:
        if size <= 0:
            return b""
        buf = create_string_buffer(size)
        error = c_void_p()
        n = self._lib.libewf_handle_read_buffer(
            self._handle, buf, c_size_t(size), byref(error)
        )
        if n < 0:
            _raise_ewf(f"libewf_handle_read_buffer({size}) failed", error)
        return buf.raw[: int(n)]

    def close(self) -> None:
        if self._handle and self._opened:
            error = c_void_p()
            self._lib.libewf_handle_close(self._handle, byref(error))
            if error:
                self._lib.libewf_error_free(byref(error))
            self._opened = False
        if self._handle:
            error = c_void_p()
            self._lib.libewf_handle_free(byref(self._handle), byref(error))
            if error:
                self._lib.libewf_error_free(byref(error))
            self._handle = c_void_p()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def handle() -> Handle:
    """Factory matching ``pyewf.handle()``."""
    return Handle()
