# CLAUDE.md — Iffy Offer Project Reference

This file is for Claude Code sessions. It documents the project structure,
how to run the tool, and how to extend it.

---

## Project Purpose

Iffy Offer analyzes a job-offer email and estimates whether it is from a
legitimate company or a phishing/scam attempt.

**What it checks:**
- Is the sender's email domain a free provider (gmail, yahoo, etc.)?
- Is the domain a known ATS/recruiting platform?
- Does the domain use homoglyph substitutions or typosquatting?
- How old is the domain (RDAP)?
- Does the domain have MX, SPF, and DMARC records?
- (Optional) Do the email headers show display-name spoofing or Reply-To hijacking?
- (Optional) Does the email body use scam-language patterns — upfront payment
  requests, premature PII/financial requests, off-platform comms pushes,
  urgency language, instant-hire claims, generic greetings?
- (Optional) Does an attachment show structural red flags — dangerous file
  types, double extensions, a file-signature/extension mismatch, VBA/XLM
  macros with auto-exec or suspicious API use, embedded PDF actions, an
  archive smuggling an executable, or a disk-image container?

**What it does NOT do:**
- Execute, open, or run an attachment (or anything inside it) — attachment
  analysis is purely static/structural, reading bytes only
- Replace an antivirus — it flags structural red flags, not known-malware
  signatures
- Click or follow links
- Connect to any external service other than public DNS and RDAP
- Guarantee accuracy — it's a heuristic tool

---

## Directory Structure

```
Iffy_Offer/
├── main.py              Entry point — creates Tk root and launches App
├── gui.py               Tkinter GUI (BSDTectApp class), dark/light mode
├── scorer.py            Aggregates check results into a risk score + verdict
├── checks/
│   ├── __init__.py      Makes 'checks' a package
│   ├── domain.py        Domain extraction, free-provider check, homoglyph/fuzzy matching
│   ├── dns_check.py     MX, SPF, DMARC DNS lookups via dnspython
│   ├── whois_check.py   Domain age via RDAP (whoisit), the successor to legacy WHOIS
│   ├── header.py        Raw email header parsing, display-name and Reply-To checks
│   ├── content.py       Email body scam-language heuristics (offline, regex/keyword only)
│   └── attachment.py    Static attachment analysis (extensions, signatures, oletools macros)
├── data/
│   ├── free_providers.txt    One domain per line; lines starting with # are comments
│   ├── ats_platforms.txt     One domain per line; same comment format
│   └── rdap_bootstrap.json   Auto-generated RDAP server cache (gitignored, not curated)
├── tests/
│   ├── test_content.py      Unit tests for checks/content.py heuristics
│   ├── test_attachment.py   Unit tests for checks/attachment.py static analysis
│   └── test_whois_check.py  Unit tests for checks/whois_check.py RDAP lookups
├── requirements.txt
├── CLAUDE.md            (this file)
└── README.md
```

---

## Running the App

```bash
# Install dependencies (one time)
pip install -r requirements.txt

# Launch the GUI
python main.py
```

Requires Python 3.10+ (uses the `X | Y` union type syntax in type hints).
Tkinter is part of the Python standard library — no extra install needed.

---

## Scoring System

Each check contributes a signed integer delta to a cumulative score.
Negative = more suspicious. Starting score is 0.

| Check                  | Delta |
|------------------------|-------|
| Free email provider    | –40   |
| Known ATS platform     | +20   |
| Homoglyph in domain    | –30   |
| Typosquatting (fuzzy)  | –25   |
| Domain < 30 days old   | –30   |
| Domain 30–180 days old | –15   |
| Domain > 2 years old   | +10   |
| No MX records          | –20   |
| No SPF record          | –10   |
| No DMARC record        | –10   |
| Reply-To mismatch      | –20   |
| Display name spoofing  | –15   |
| Body: upfront payment request      | –35   |
| Body: premature PII/financial ask  | –25   |
| Body: instant hire, no interview   | –15   |
| Body: off-platform comms push      | –15   |
| Body: urgency/pressure language    | –10   |
| Body: generic greeting             | –5    |
| Attachment: dangerous/double extension | –35   |
| Attachment: signature mismatch         | –30   |
| Attachment: archive has executable     | –30   |
| Attachment: macros, high risk          | –40   |
| Attachment: macros, medium risk        | –25   |
| Attachment: macros, low risk           | –15   |
| Attachment: PDF embedded action/JS     | –25   |
| Attachment: disk-image container       | –20   |

**Verdict bands:**
- Score ≥ 0    → Looks Legit (green)
- –1 to –29   → Iffy (yellow)
- ≤ –30        → Yikes! (red)

Thresholds and deltas are defined in `scorer.py` — easy to adjust.

---

## Adding a New Check

1. Write the check function in the appropriate `checks/` module (or create a new one).
   - Return a dict with at least `'detail': str`.
   - Return `None` or a sentinel value for inconclusive results — never crash.

2. Call the function in `gui.py → _run_analysis_worker()` and pass the result to
   `build_score()` in `scorer.py`.

3. Add a new `if/elif/else` block in `scorer.py → build_score()` to map the result
   to a `CheckResult` with a chosen delta.

4. Update the score table in this file.

---

## Data Files

`data/free_providers.txt` and `data/ats_platforms.txt` are plain-text lists.
- One entry per line
- Lines beginning with `#` are comments (ignored)
- All entries are lowercased at load time

To add a new provider or platform, just add a line — no code changes needed.

`data/rdap_bootstrap.json` is different: it's an auto-generated cache of
IANA's RDAP bootstrap registry (which RDAP server handles which TLD),
fetched by `checks/whois_check.py` on first use and refreshed automatically
after 30 days. It's gitignored — nothing to hand-edit or commit here.

---

## Attachment Analysis Safety

`checks/attachment.py` only reads attachment bytes and parses file structure
(via the `oletools` package for Office macros, plus stdlib `zipfile` and magic-byte
checks). It never executes, opens, or launches the attachment or anything
inside it. Every parsing step is wrapped in `try/except` and degrades to an
`'unknown'` result on malformed input — the same "never crash" rule as
RDAP/DNS lookups, since real malicious samples often use deliberately
malformed files to break naive parsers. Files above 50 MB are skipped rather
than analyzed.

---

## Threading Model

DNS and RDAP lookups, body-language analysis, and attachment analysis all run
in a `threading.Thread` (daemon) started from `gui.py → _start_analysis()`.
Results are passed back to the main (UI) thread via a `queue.Queue` and polled
with `root.after(100, ...)`.

**Never call Tkinter widget methods from the worker thread** — Tkinter is not
thread-safe. All UI updates happen in `_poll_result_queue()` on the main thread.

---

## Theme System

Two palette dicts (`DARK_PALETTE`, `LIGHT_PALETTE`) in `gui.py` define all colors.
`_apply_theme()` walks all widgets and re-applies colors from the active palette.
To change a color, edit the dict. To add a new semantic color, add a key to
both dicts and reference it in `_apply_theme()`.
