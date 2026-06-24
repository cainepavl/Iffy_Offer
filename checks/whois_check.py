"""
checks/whois_check.py
---------------------
Checks how old the sender's domain is using WHOIS data.

Why domain age matters:
  Scammers register fresh domains specifically for phishing campaigns and
  abandon them once they're blocked or reported. A domain created last week
  sending "urgent job offers" is highly suspicious.

  Legitimate companies typically have domains that are months or years old.
  A startup might have a young domain, so youth alone isn't proof of fraud —
  it's one signal among several.

Age thresholds used (and why):
  < 30 days  → Critical flag. Almost no legitimate business recruits within
               a month of registering its domain.
  30–180 days → Yellow flag. Could be a legitimate startup, but warrants caution.
  > 180 days → No penalty. Domain has some history.
  > 2 years  → Small positive signal. Long-standing domains are harder to fake.

WHOIS limitations:
  - Some TLDs (especially newer gTLDs and some ccTLDs) block or restrict WHOIS.
  - Registrars sometimes redact creation dates for privacy.
  - In these cases we return None (unknown) rather than a false result.
"""

import whois
import contextlib
import io
from datetime import datetime, timezone


def get_domain_age(domain: str) -> dict:
    """
    Look up the WHOIS registration date for a domain and compute its age.

    Returns a dict:
        {
            'age_days'        : int | None,   # None if we couldn't determine age
            'creation_date'   : str | None,   # ISO date string of registration
            'registrar'       : str | None,   # Registrar name if available
            'detail'          : str,          # Human-readable summary
        }
    """
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            w = whois.whois(domain)
    except Exception as e:
        # WHOIS can fail for many reasons: network errors, blocked queries,
        # unsupported TLD, rate limiting. Treat as inconclusive.
        # We truncate the exception message because some WHOIS libraries embed
        # the full raw server response inside the exception string.
        short_msg = str(e).splitlines()[0][:120]
        return {
            'age_days':      None,
            'creation_date': None,
            'registrar':     None,
            'detail': f'WHOIS lookup failed for "{domain}": {type(e).__name__} — {short_msg}',
        }

    # python-whois sometimes returns a list of dates (e.g. for domains with
    # multiple WHOIS servers returning slightly different values). We take the
    # earliest date as the authoritative creation date.
    creation = w.creation_date
    if isinstance(creation, list):
        creation = min(creation)   # earliest date in the list

    if creation is None:
        return {
            'age_days':      None,
            'creation_date': None,
            'registrar':     _safe_registrar(w),
            'detail': f'WHOIS returned no creation date for "{domain}" (privacy shield or unsupported TLD).',
        }

    # Normalise to UTC-aware datetime so comparison with now() works correctly
    if hasattr(creation, 'tzinfo') and creation.tzinfo is None:
        # Naive datetime — assume UTC (most WHOIS servers report UTC)
        creation = creation.replace(tzinfo=timezone.utc)

    now = datetime.now(tz=timezone.utc)
    age_days = (now - creation).days

    creation_str = creation.strftime('%Y-%m-%d')
    registrar    = _safe_registrar(w)

    # Build a human-readable summary with the age context
    if age_days < 30:
        age_label = f'{age_days} days old — VERY NEW (critical red flag)'
    elif age_days < 180:
        age_label = f'{age_days} days old — relatively new (yellow flag)'
    elif age_days < 730:
        # Between 6 months and 2 years — acceptable range, no comment
        age_label = f'{age_days} days old (~{age_days // 30} months)'
    else:
        years = age_days / 365
        age_label = f'{age_days} days old (~{years:.1f} years) — established domain'

    detail = f'Domain registered {creation_str} ({age_label}).'
    if registrar:
        detail += f' Registrar: {registrar}.'

    return {
        'age_days':      age_days,
        'creation_date': creation_str,
        'registrar':     registrar,
        'detail':        detail,
    }


def _safe_registrar(whois_result) -> str | None:
    """
    Safely extract the registrar name from a WHOIS result.
    python-whois can return None, a string, or a list — handle all cases.
    """
    registrar = getattr(whois_result, 'registrar', None)
    if registrar is None:
        return None
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None
    return str(registrar).strip() if registrar else None
