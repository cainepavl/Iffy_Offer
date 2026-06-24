"""
checks/domain.py
----------------
Analyzes the sender's email domain against the claimed company name.

Three distinct checks live here:
  1. Free provider detection — is this a gmail/yahoo/etc. address?
  2. Known ATS platform detection — is this a trusted recruiting tool?
  3. Domain vs company name comparison — typosquatting and homoglyph detection.

All functions return plain data (strings, bools, dicts) so the GUI and scorer
can display and weight the results however they like.
"""

import re
import os

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # python-Levenshtein is the preferred fast C extension, but if it's missing
    # we fall back to difflib so the app still launches. Install the package from
    # requirements.txt to get the faster implementation.
    from difflib import SequenceMatcher as _SM
    def levenshtein_distance(a: str, b: str) -> int:
        ratio = _SM(None, a, b).ratio()
        return round((1 - ratio) * max(len(a), len(b)))


# ---------------------------------------------------------------------------
# Homoglyph substitution map
# Scammers replace characters with visually similar ones to fool a quick glance.
# For example: "amaz0n.com" looks like "amazon.com" at a glance.
# We normalize both the domain and a clean version of it so we can compare them.
#
# Key   = the fake character(s) a scammer uses
# Value = the real character(s) it mimics
# ---------------------------------------------------------------------------
HOMOGLYPH_MAP = {
    '0':  'o',   # zero → letter o
    '1':  'l',   # one  → lowercase L
    '|':  'l',   # pipe → lowercase L
    '3':  'e',   # three → e
    '4':  'a',   # four  → a (less common but seen)
    '5':  's',   # five  → s
    '6':  'b',   # six   → b (in some fonts)
    'rn': 'm',   # "rn" side-by-side → m  (classic trick: "arnazon.com")
    'vv': 'w',   # two v's → w
    'cl': 'd',   # c followed by l → d (in some fonts)
    'ii': 'n',   # two i's → n (rare but documented)
}


def _load_list(filename: str) -> set:
    """
    Load a plain-text data file (one entry per line) into a set of lowercase strings.
    Lines starting with '#' and blank lines are skipped — they're comments/whitespace.

    We use a set for O(1) membership testing (important if the lists grow large).
    """
    # Build the path relative to this file so it works regardless of where
    # the user runs the script from.
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    filepath = os.path.join(data_dir, filename)

    entries = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comment lines and blank lines
                if line and not line.startswith('#'):
                    entries.add(line.lower())
    except FileNotFoundError:
        # If the data file is missing, return an empty set so checks degrade
        # gracefully rather than crashing the whole program.
        pass
    return entries


# Load the lists once at module import time so we don't re-read the files
# on every check call. These are module-level constants.
FREE_PROVIDERS = _load_list('free_providers.txt')
ATS_PLATFORMS  = _load_list('ats_platforms.txt')


def extract_domain(email_address: str) -> str | None:
    """
    Pull the domain portion out of an email address.

    Returns the domain string (lowercased) or None if the address is malformed.

    Examples:
        "Recruiter <hr@Amazon.com>"  →  "amazon.com"
        "noreply@greenhouse.io"      →  "greenhouse.io"
        "not-an-email"               →  None
    """
    # Strip surrounding whitespace and angle-bracket formatting first.
    # Some email clients show "Display Name <actual@email.com>".
    email_address = email_address.strip()

    # Extract just the email if it's wrapped in angle brackets
    angle_match = re.search(r'<([^>]+)>', email_address)
    if angle_match:
        email_address = angle_match.group(1).strip()

    # Standard email format: local-part@domain
    if '@' not in email_address:
        return None

    parts = email_address.rsplit('@', 1)  # rsplit so we only split on the last '@'
    if len(parts) != 2 or not parts[1]:
        return None

    return parts[1].lower()


def is_free_provider(domain: str) -> bool:
    """
    Return True if the domain is a known free/consumer email provider.

    Legitimate companies virtually never recruit directly from gmail, yahoo,
    hotmail, etc. If a job offer comes from one of these, treat it as a
    strong red flag regardless of everything else.
    """
    return domain.lower() in FREE_PROVIDERS


def is_ats_platform(domain: str) -> bool:
    """
    Return True if the domain is a known Applicant Tracking System or
    job-board platform (Greenhouse, Workday, LinkedIn, etc.).

    Many legitimate companies outsource their hiring pipeline to these
    platforms, so email FROM one of them is a positive trust signal.

    Note: We check if the domain *ends with* an ATS entry so that
    subdomain variants (e.g. "mail.greenhouse.io") are also matched.
    """
    domain = domain.lower()
    for platform in ATS_PLATFORMS:
        # Exact match OR subdomain of the platform (e.g. "mail.greenhouse.io")
        if domain == platform or domain.endswith('.' + platform):
            return True
    return False


def normalize_homoglyphs(text: str) -> str:
    """
    Replace known homoglyph characters in `text` with their real equivalents.

    We apply multi-character substitutions (like 'rn'→'m') before single-character
    ones to avoid partial replacements breaking the longer patterns.

    Example:
        "arnaz0n-careers" → "amazon-careers"
    """
    text = text.lower()

    # Sort by length descending so multi-char patterns are replaced first.
    # If we did single chars first, 'r' and 'n' might get replaced individually
    # before we have a chance to catch 'rn' as a unit.
    for fake, real in sorted(HOMOGLYPH_MAP.items(), key=lambda x: -len(x[0])):
        text = text.replace(fake, real)

    return text


def _domain_stem(domain: str) -> str:
    """
    Strip the TLD (and any subdomains) from a domain to get the core name.

    We use a simple heuristic: take the second-to-last label.
    This works for common TLDs (.com, .io, .net, .org) and most ccTLDs.
    It doesn't handle compound TLDs like .co.uk perfectly, but that's an
    acceptable trade-off for a heuristic tool.

    Examples:
        "amazon.com"          → "amazon"
        "mail.greenhouse.io"  → "greenhouse"
        "amaz0n-jobs.net"     → "amaz0n-jobs"
    """
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        return parts[-2]   # e.g. "amazon" from ["amazon", "com"]
    return domain


def check_domain_vs_company(domain: str, company_name: str) -> dict:
    """
    Compare the email domain against the claimed company name to detect
    typosquatting and homoglyph spoofing.

    Returns a dict with:
        'homoglyph_detected' : bool   — homoglyph substitution found in domain
        'fuzzy_match'        : bool   — domain suspiciously close to company name
        'edit_distance'      : int    — Levenshtein distance (lower = more suspicious)
        'normalized_domain'  : str    — domain after homoglyph normalization
        'detail'             : str    — human-readable explanation

    Strategy:
        1. Normalize both the domain stem and the company name tokens.
        2. Check if normalizing the domain changes it (= homoglyphs present).
        3. Compute edit distance between the cleaned domain stem and each
           significant word in the company name.
        4. A low edit distance on a domain that doesn't exactly match suggests
           intentional typosquatting.
    """
    stem = _domain_stem(domain)
    normalized_stem = normalize_homoglyphs(stem)

    # Check if normalization changed the stem — if so, there are homoglyphs
    homoglyph_detected = (normalized_stem != stem)

    # Tokenize the company name: lowercase, split on spaces and punctuation,
    # drop short/trivial words like "Inc", "LLC", "Corp", "Ltd", "the", "and"
    stop_tokens = {'inc', 'llc', 'corp', 'ltd', 'co', 'the', 'and', 'group', 'company'}
    company_tokens = [
        tok for tok in re.split(r'[\s\W]+', company_name.lower())
        if len(tok) > 2 and tok not in stop_tokens
    ]

    if not company_tokens:
        # Company name was all stop words or very short — can't compare meaningfully
        return {
            'homoglyph_detected': homoglyph_detected,
            'fuzzy_match': False,
            'edit_distance': None,
            'normalized_domain': normalized_stem,
            'detail': 'Company name too short to compare meaningfully.'
        }

    # Split the domain stem on hyphens so that "amzon-careers.net" gives us
    # the sub-token "amzon" to compare against "amazon", rather than comparing
    # the entire string "amzon-careers" (which inflates the edit distance by
    # the length of the suffix and masks the typosquatting).
    # We also include the full normalized stem as a candidate.
    domain_tokens = [normalized_stem] + [
        part for part in re.split(r'[-_]', normalized_stem)
        if len(part) > 2
    ]

    # Find the minimum edit distance between any domain token and any
    # significant company name token. Both sides are already normalized.
    min_distance = min(
        levenshtein_distance(d_tok, c_tok)
        for d_tok in domain_tokens
        for c_tok in company_tokens
    )

    # Thresholds for "suspicious" edit distance:
    #   0 = exact match after normalization → domain looks legit (or is a perfect spoof)
    #   1–3 = very close → likely typosquatting (e.g. "amzon", "amozon", "amazone")
    #   4+ = not related enough to flag
    #
    # We only flag as fuzzy if there's SOME similarity but not an exact match,
    # because an exact match means the domain genuinely corresponds to the company.
    fuzzy_match = 1 <= min_distance <= 3

    # Build a human-readable detail string
    if homoglyph_detected and fuzzy_match:
        detail = (
            f'Domain stem "{stem}" contains homoglyph substitutions '
            f'(normalized: "{normalized_stem}") and is very close to '
            f'"{company_name}" (edit distance {min_distance}).'
        )
    elif homoglyph_detected:
        detail = (
            f'Domain stem "{stem}" contains homoglyph substitutions '
            f'(normalized: "{normalized_stem}"). This is a common spoofing tactic.'
        )
    elif fuzzy_match:
        detail = (
            f'Domain stem "{stem}" is very similar to "{company_name}" '
            f'(edit distance {min_distance}) — possible typosquatting.'
        )
    else:
        detail = (
            f'Domain stem "{stem}" does not appear to impersonate "{company_name}" '
            f'(minimum edit distance: {min_distance}).'
        )

    return {
        'homoglyph_detected': homoglyph_detected,
        'fuzzy_match': fuzzy_match,
        'edit_distance': min_distance,
        'normalized_domain': normalized_stem,
        'detail': detail,
    }
