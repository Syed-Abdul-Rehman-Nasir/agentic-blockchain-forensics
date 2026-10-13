"""Deterministic Chroma document ID helpers (offline, no embedder required)."""

from __future__ import annotations

from ai_service.rag.vector_store import file_document_id


def test_file_document_id_is_stable_across_calls():
    path = "/Documents and Settings/Mr. Evil/My Documents/notes.txt"
    first = file_document_id("CASE_A", path)
    second = file_document_id("CASE_A", path)
    assert first == second
    assert first.startswith("CASE_A_file_")
    assert len(first.rsplit("_", 1)[-1]) == 16


def test_file_document_id_differs_by_path_and_case():
    a = file_document_id("CASE_A", "/Windows/System32/cmd.exe")
    b = file_document_id("CASE_A", "/Windows/System32/notepad.exe")
    c = file_document_id("CASE_B", "/Windows/System32/cmd.exe")
    assert a != b
    assert a != c
