"""
checks/attachment.py
---------------------
Static, read-only analysis of a job-offer email's attachment.

CRITICAL SAFETY RULE: nothing in this module ever executes, opens (with its
associated application), or otherwise runs the attachment. Every check here
only reads raw bytes and parses file structure -- the same posture a
malware analyst takes with an unknown sample. This is a heuristic scanner,
not an antivirus replacement: it flags structural red flags (dangerous file
types, macro presence, embedded actions), not known-malware signatures.

Malformed or deliberately corrupted files are common with real malicious
samples (parsers are a favorite attack surface), so every parsing step is
wrapped in try/except and degrades to an 'unknown'/inconclusive result
rather than raising -- the same rule CLAUDE.md already applies to WHOIS/DNS
lookups.

analyze_attachment() is only meant to be called when the user actually
selected a file -- same optionality as the body/header checks.
"""

import os
import re
import zipfile

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    # If oletools somehow isn't installed, macro analysis degrades to
    # 'unknown' instead of crashing the whole tool.
    VBA_Parser = None


# Refuse to parse anything bigger than this -- large files aren't realistic
# email attachments, and we don't want a single scan to hang the worker
# thread or exhaust memory.
MAX_ANALYZE_BYTES = 50 * 1024 * 1024  # 50 MB

# Extensions that can execute code directly if double-clicked.
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.js', '.jse', '.vbs',
    '.vbe', '.wsf', '.wsh', '.ps1', '.psm1', '.jar', '.msi', '.msp',
    '.reg', '.hta', '.cpl', '.dll', '.gadget', '.lnk',
}

# Extensions a recipient would trust at a glance -- used to detect the
# "resume.pdf.exe" double-extension trick.
TRUSTED_LOOKING_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt',
    '.jpg', '.jpeg', '.png', '.csv', '.rtf',
}

# Office formats that can carry VBA/XLM macros -- everything else skips
# macro analysis entirely (macro_analysis will be None).
OFFICE_MACRO_EXTENSIONS = {
    '.doc', '.dot', '.docm', '.dotm',
    '.xls', '.xlt', '.xlsm', '.xltm', '.xlsb',
    '.ppt', '.pot', '.pptm', '.potm',
    '.rtf',
}

# Disk-image container formats -- legitimate HR documents are essentially
# never distributed this way; it's a known malware-delivery pattern used to
# smuggle payloads past mail-filter extension blocks.
CONTAINER_EXTENSIONS = {'.iso', '.img', '.vhd', '.vhdx'}

# Magic-byte signatures -> file type label, checked longest-prefix first.
_SIGNATURES = [
    (b'%PDF', 'pdf'),
    (b'PK\x03\x04', 'zip'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole2'),
    (b'MZ', 'pe'),
    (b'\x7fELF', 'elf'),
    (b'\xff\xd8\xff', 'jpeg'),
    (b'\x89PNG\r\n\x1a\n', 'png'),
    (b'GIF87a', 'gif'),
    (b'GIF89a', 'gif'),
]

# What signature we'd expect for a given extension, if we have an opinion.
_EXPECTED_SIGNATURE_BY_EXT = {
    '.pdf': 'pdf',
    '.doc': 'ole2', '.xls': 'ole2', '.ppt': 'ole2', '.msi': 'ole2',
    '.docx': 'zip', '.xlsx': 'zip', '.pptx': 'zip',
    '.docm': 'zip', '.xlsm': 'zip', '.pptm': 'zip', '.zip': 'zip',
    '.jpg': 'jpeg', '.jpeg': 'jpeg',
    '.png': 'png',
    '.gif': 'gif',
    '.exe': 'pe', '.dll': 'pe', '.scr': 'pe',
}

# PDF keywords indicating embedded scripts or automatic actions.
_PDF_SUSPICIOUS_KEYWORDS = [
    b'/JavaScript', b'/JS', b'/OpenAction', b'/Launch', b'/EmbeddedFile', b'/AA',
]


def _detect_signature(data: bytes) -> str | None:
    """Return a file-type label based on magic bytes, or None if unrecognized."""
    for magic, label in _SIGNATURES:
        if data.startswith(magic):
            return label
    return None


def _split_extensions(filename: str) -> tuple[str, str]:
    """
    Return (second_to_last_ext, last_ext), lowercased with leading dots,
    e.g. 'resume.pdf.exe' -> ('.pdf', '.exe'). Missing parts are ''.
    """
    parts = filename.lower().split('.')
    last_ext = '.' + parts[-1] if len(parts) > 1 else ''
    second_ext = '.' + parts[-2] if len(parts) > 2 else ''
    return second_ext, last_ext


def check_extension(filename: str) -> dict:
    """
    Flag known-dangerous extensions and the 'trusted-name.pdf.exe'
    double-extension trick.
    """
    second_ext, last_ext = _split_extensions(filename)

    dangerous = last_ext in DANGEROUS_EXTENSIONS
    double_extension = second_ext in TRUSTED_LOOKING_EXTENSIONS and last_ext in DANGEROUS_EXTENSIONS

    detected = dangerous or double_extension
    if double_extension:
        detail = (
            f'Filename uses a double extension ("{second_ext}{last_ext}") -- a '
            f'classic trick to make a "{last_ext}" file look like a harmless '
            f'"{second_ext}" document.'
        )
    elif dangerous:
        detail = f'"{last_ext}" is a directly executable/script file type.'
    else:
        detail = f'"{last_ext or "(no extension)"}" is not a known-dangerous file type.'

    return {'detected': detected, 'matches': [last_ext] if dangerous else [], 'detail': detail}


def check_signature_mismatch(filename: str, data: bytes) -> dict:
    """
    Compare the file's magic-byte signature against what its extension
    claims to be, e.g. a ".pdf" that's actually a Windows executable.
    """
    _, last_ext = _split_extensions(filename)
    expected = _EXPECTED_SIGNATURE_BY_EXT.get(last_ext)
    actual = _detect_signature(data)

    if expected is None or actual is None:
        return {
            'detected': False,
            'matches': [],
            'detail': 'Not enough information to compare claimed vs. actual file type.',
        }

    detected = actual != expected
    detail = (
        f'File is named "{last_ext}" but its content signature looks like a '
        f'"{actual}" file, not a "{expected}" file.'
        if detected else
        f'File content matches its "{last_ext}" extension.'
    )
    return {'detected': detected, 'matches': [actual] if detected else [], 'detail': detail}


def check_macros(filename: str, file_path: str) -> dict | None:
    """
    Run oletools/olevba against Office-format files to detect VBA/XLM
    macros, auto-exec triggers, and suspicious API usage. Returns None for
    file types that can't contain macros.
    """
    _, last_ext = _split_extensions(filename)
    if last_ext not in OFFICE_MACRO_EXTENSIONS:
        return None

    if VBA_Parser is None:
        return {
            'detected': None, 'severity': 'unknown', 'matches': [],
            'detail': 'oletools is not installed -- macro analysis unavailable.',
        }

    try:
        parser = VBA_Parser(file_path)
        try:
            if not parser.detect_vba_macros():
                return {
                    'detected': False, 'severity': 'none', 'matches': [],
                    'detail': 'No VBA/XLM macros found.',
                }

            findings = parser.analyze_macros()  # list of (kind, keyword, description)
            autoexec = [f'{kw}: {desc}' for kind, kw, desc in findings if kind == 'AutoExec']
            suspicious = [f'{kw}: {desc}' for kind, kw, desc in findings if kind == 'Suspicious']

            if autoexec and suspicious:
                severity = 'high'
            elif autoexec or suspicious:
                severity = 'medium'
            else:
                severity = 'low'

            matches = (autoexec + suspicious)[:10]
            detail = (
                f'Macros found ({severity} risk): '
                f'{len(autoexec)} auto-exec trigger(s), {len(suspicious)} suspicious '
                f'API call(s).'
            )
            return {'detected': True, 'severity': severity, 'matches': matches, 'detail': detail}
        finally:
            parser.close()
    except Exception as e:
        return {
            'detected': None, 'severity': 'unknown', 'matches': [],
            'detail': f'Macro analysis failed (corrupt or unsupported file): {type(e).__name__}',
        }


def check_pdf_actions(filename: str, data: bytes) -> dict | None:
    """
    Byte-level scan for PDF keywords indicating embedded JavaScript or
    automatic launch/open actions. Returns None for non-PDF files.
    """
    _, last_ext = _split_extensions(filename)
    if last_ext != '.pdf' and _detect_signature(data) != 'pdf':
        return None

    found = sorted({kw.decode() for kw in _PDF_SUSPICIOUS_KEYWORDS if kw in data})
    detected = bool(found)
    detail = (
        f'PDF contains embedded action/script keywords: {", ".join(found)}.'
        if detected else
        'No embedded JavaScript or automatic-action keywords found in the PDF.'
    )
    return {'detected': detected, 'matches': found, 'detail': detail}


def check_archive_contents(filename: str, file_path: str) -> dict | None:
    """
    For ZIP archives, list members and flag any executable/script file
    inside -- a common trick to smuggle an attachment past mail filters
    that block dangerous extensions directly. Returns None for non-ZIP files.
    """
    _, last_ext = _split_extensions(filename)
    if last_ext != '.zip':
        return None

    try:
        with zipfile.ZipFile(file_path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError) as e:
        return {
            'detected': None, 'matches': [], 'detail': f'Could not read zip contents: {type(e).__name__}',
        }

    dangerous_members = [
        n for n in names
        if os.path.splitext(n.lower())[1] in DANGEROUS_EXTENSIONS
    ]
    detected = bool(dangerous_members)
    detail = (
        f'Zip archive contains executable/script file(s): {", ".join(dangerous_members)}.'
        if detected else
        'No executable/script files found inside the zip archive.'
    )
    return {'detected': detected, 'matches': dangerous_members, 'detail': detail}


def check_container_type(filename: str) -> dict | None:
    """
    Flag disk-image container attachments (.iso/.img/.vhd/.vhdx) outright.
    Returns None for any other file type.
    """
    _, last_ext = _split_extensions(filename)
    if last_ext not in CONTAINER_EXTENSIONS:
        return None

    return {
        'detected': True,
        'matches': [last_ext],
        'detail': (
            f'Attachment is a disk-image container ("{last_ext}") -- legitimate '
            f'HR documents are essentially never distributed this way. This is a '
            f'known technique for smuggling malicious payloads past mail filters.'
        ),
    }


def analyze_attachment(file_path: str) -> dict:
    """
    Run all attachment checks and return a dict of sub-check results, keyed
    by check name. Sub-checks that don't apply to this file type return
    None. If the file can't be read at all (too large, missing, unreadable),
    'error' is set and every other key is None.
    """
    result = {
        'error': None,
        'extension_flag': None,
        'signature_mismatch': None,
        'macro_analysis': None,
        'pdf_action_flag': None,
        'archive_contents': None,
        'container_flag': None,
    }

    filename = os.path.basename(file_path)

    try:
        size = os.path.getsize(file_path)
    except OSError as e:
        result['error'] = f'Could not access file: {type(e).__name__}'
        return result

    if size > MAX_ANALYZE_BYTES:
        result['error'] = (
            f'File is too large to analyze ({size // (1024 * 1024)} MB, '
            f'limit {MAX_ANALYZE_BYTES // (1024 * 1024)} MB).'
        )
        return result

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except OSError as e:
        result['error'] = f'Could not read file: {type(e).__name__}'
        return result

    result['extension_flag'] = check_extension(filename)
    result['signature_mismatch'] = check_signature_mismatch(filename, data)
    result['macro_analysis'] = check_macros(filename, file_path)
    result['pdf_action_flag'] = check_pdf_actions(filename, data)
    result['archive_contents'] = check_archive_contents(filename, file_path)
    result['container_flag'] = check_container_type(filename)

    return result
