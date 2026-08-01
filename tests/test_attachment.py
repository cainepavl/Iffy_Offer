"""
Tests for checks/attachment.py

Covers extension/signature/archive/container heuristics against real temp
files on disk, plus the oletools-backed macro_analysis path (mocked, since
constructing a real VBA-bearing document from scratch is out of scope for a
unit test). No file is ever executed or opened with its associated app --
these tests only exercise the static byte/structure parsing.
"""

import zipfile

import pytest

import checks.attachment as attachment
from checks.attachment import (
    check_extension,
    check_signature_mismatch,
    check_macros,
    check_pdf_actions,
    check_archive_contents,
    check_container_type,
    analyze_attachment,
)


# ---------------------------------------------------------------------------
# check_extension
# ---------------------------------------------------------------------------

class TestCheckExtension:
    def test_dangerous_extension_flagged(self):
        result = check_extension("invoice.exe")
        assert result["detected"] is True

    def test_double_extension_flagged(self):
        result = check_extension("resume.pdf.exe")
        assert result["detected"] is True
        assert "pdf" in result["detail"]

    def test_benign_extension_not_flagged(self):
        result = check_extension("resume.pdf")
        assert result["detected"] is False

    def test_no_extension_not_flagged(self):
        result = check_extension("resume")
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# check_signature_mismatch
# ---------------------------------------------------------------------------

class TestCheckSignatureMismatch:
    def test_matching_pdf_not_flagged(self):
        result = check_signature_mismatch("offer.pdf", b"%PDF-1.4 rest of file")
        assert result["detected"] is False

    def test_exe_disguised_as_pdf_flagged(self):
        result = check_signature_mismatch("offer.pdf", b"MZ\x90\x00\x03\x00\x00\x00")
        assert result["detected"] is True
        assert "pe" in result["matches"]

    def test_unknown_extension_not_flagged(self):
        result = check_signature_mismatch("notes.xyz", b"some random bytes")
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# check_pdf_actions
# ---------------------------------------------------------------------------

class TestCheckPdfActions:
    def test_clean_pdf_not_flagged(self):
        result = check_pdf_actions("offer.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj")
        assert result is not None
        assert result["detected"] is False

    def test_embedded_javascript_flagged(self):
        result = check_pdf_actions("offer.pdf", b"%PDF-1.4\n/OpenAction << /S /JavaScript /JS (app.alert(1)) >>")
        assert result is not None
        assert result["detected"] is True

    def test_non_pdf_returns_none(self):
        result = check_pdf_actions("resume.docx", b"PK\x03\x04 fake docx bytes")
        assert result is None


# ---------------------------------------------------------------------------
# check_archive_contents
# ---------------------------------------------------------------------------

class TestCheckArchiveContents:
    def test_zip_with_executable_flagged(self, tmp_path):
        zip_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("resume.txt", "just a resume")
            zf.writestr("run_me.exe", b"MZ fake exe bytes")

        result = check_archive_contents("bundle.zip", str(zip_path))
        assert result["detected"] is True
        assert "run_me.exe" in result["matches"]

    def test_zip_without_executable_not_flagged(self, tmp_path):
        zip_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("resume.txt", "just a resume")

        result = check_archive_contents("bundle.zip", str(zip_path))
        assert result["detected"] is False

    def test_corrupt_zip_degrades_gracefully(self, tmp_path):
        bad_zip = tmp_path / "broken.zip"
        bad_zip.write_bytes(b"not actually a zip file")

        result = check_archive_contents("broken.zip", str(bad_zip))
        assert result["detected"] is None

    def test_non_zip_returns_none(self, tmp_path):
        result = check_archive_contents("resume.pdf", str(tmp_path / "resume.pdf"))
        assert result is None


# ---------------------------------------------------------------------------
# check_container_type
# ---------------------------------------------------------------------------

class TestCheckContainerType:
    def test_iso_flagged(self):
        result = check_container_type("onboarding_docs.iso")
        assert result is not None
        assert result["detected"] is True

    def test_docx_returns_none(self):
        result = check_container_type("offer.docx")
        assert result is None


# ---------------------------------------------------------------------------
# check_macros (oletools mocked -- see module docstring)
# ---------------------------------------------------------------------------

class _FakeVBAParser:
    def __init__(self, has_macros, findings=None, raise_on_init=False):
        if raise_on_init:
            raise RuntimeError("simulated corrupt file")
        self._has_macros = has_macros
        self._findings = findings or []

    def detect_vba_macros(self):
        return self._has_macros

    def analyze_macros(self):
        return self._findings

    def close(self):
        pass


class TestCheckMacros:
    def test_non_office_extension_returns_none(self, tmp_path):
        result = check_macros("photo.png", str(tmp_path / "photo.png"))
        assert result is None

    def test_no_macros_found(self, monkeypatch, tmp_path):
        monkeypatch.setattr(attachment, "VBA_Parser", lambda path: _FakeVBAParser(has_macros=False))
        result = check_macros("offer.docm", str(tmp_path / "offer.docm"))
        assert result["detected"] is False

    def test_high_severity_autoexec_and_suspicious(self, monkeypatch, tmp_path):
        findings = [
            ("AutoExec", "AutoOpen", "Runs when the document is opened"),
            ("Suspicious", "Shell", "May run an executable file or a system command"),
        ]
        monkeypatch.setattr(
            attachment, "VBA_Parser",
            lambda path: _FakeVBAParser(has_macros=True, findings=findings),
        )
        result = check_macros("offer.docm", str(tmp_path / "offer.docm"))
        assert result["detected"] is True
        assert result["severity"] == "high"

    def test_low_severity_benign_macros(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            attachment, "VBA_Parser",
            lambda path: _FakeVBAParser(has_macros=True, findings=[]),
        )
        result = check_macros("offer.docm", str(tmp_path / "offer.docm"))
        assert result["detected"] is True
        assert result["severity"] == "low"

    def test_corrupt_file_degrades_to_unknown(self, monkeypatch, tmp_path):
        def _raise(path):
            raise RuntimeError("simulated corrupt file")
        monkeypatch.setattr(attachment, "VBA_Parser", _raise)
        result = check_macros("offer.docm", str(tmp_path / "offer.docm"))
        assert result["detected"] is None
        assert result["severity"] == "unknown"


# ---------------------------------------------------------------------------
# analyze_attachment (end-to-end wiring)
# ---------------------------------------------------------------------------

class TestAnalyzeAttachment:
    def test_missing_file_sets_error(self, tmp_path):
        result = analyze_attachment(str(tmp_path / "does_not_exist.txt"))
        assert result["error"] is not None
        assert result["extension_flag"] is None

    def test_oversized_file_sets_error(self, tmp_path, monkeypatch):
        path = tmp_path / "huge.txt"
        path.write_text("small on disk, pretend huge")
        monkeypatch.setattr(attachment.os.path, "getsize", lambda p: attachment.MAX_ANALYZE_BYTES + 1)
        result = analyze_attachment(str(path))
        assert result["error"] is not None
        assert "too large" in result["error"].lower()

    def test_plain_text_file_has_no_type_specific_checks(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("just some plain notes, nothing dangerous")
        result = analyze_attachment(str(path))
        assert result["error"] is None
        assert result["extension_flag"]["detected"] is False
        assert result["macro_analysis"] is None
        assert result["pdf_action_flag"] is None
        assert result["archive_contents"] is None
        assert result["container_flag"] is None

    def test_dangerous_file_flagged_end_to_end(self, tmp_path):
        path = tmp_path / "invoice.exe"
        path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00 fake exe bytes")
        result = analyze_attachment(str(path))
        assert result["error"] is None
        assert result["extension_flag"]["detected"] is True
