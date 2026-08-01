"""
checks/whois_check.py
----------------------
Checks how old the sender's domain is using RDAP (Registration Data Access
Protocol) -- the modern successor to legacy WHOIS. ICANN sunset the legacy
WHOIS protocol (port 43) for most gTLDs in early 2025 in favor of RDAP, so
this module queries RDAP directly via the `whoisit` package rather than the
old WHOIS protocol, which is increasingly unsupported.

Why domain age matters:
  Scammers register fresh domains specifically for phishing campaigns and
  abandon them once they're blocked or reported. A domain created last week
  sending "urgent job offers" is highly suspicious.

  Legitimate companies typically have domains that are months or years old.
  A startup might have a young domain, so youth alone isn't proof of fraud --
  it's one signal among several.

Age thresholds used (and why):
  < 30 days  -> Critical flag. Almost no legitimate business recruits within
               a month of registering its domain.
  30-180 days -> Yellow flag. Could be a legitimate startup, but warrants caution.
  > 180 days -> No penalty. Domain has some history.
  > 2 years  -> Small positive signal. Long-standing domains are harder to fake.

RDAP bootstrap data (which RDAP server handles which TLD) is fetched from
IANA once and cached to disk (data/rdap_bootstrap.json) so we don't hit IANA
on every single lookup. The cache is refreshed automatically once it's more
than BOOTSTRAP_MAX_AGE_DAYS old; if a refresh attempt fails, we keep using
the stale cache rather than having no bootstrap data at all.

RDAP limitations:
  - Not every TLD has an RDAP server yet, though coverage is now the vast
    majority of gTLDs and a growing set of ccTLDs.
  - Some registries redact registration dates for privacy (GDPR etc).
  - In these cases we return None (unknown) rather than a false result --
    same "never crash" rule as the rest of checks/.
"""

import os
from datetime import datetime, timezone

import whoisit

BOOTSTRAP_CACHE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'rdap_bootstrap.json')
BOOTSTRAP_MAX_AGE_DAYS = 30


def _ensure_bootstrapped():
    """
    Load RDAP bootstrap data (TLD -> RDAP server mapping) from a local cache
    if present, refreshing from IANA if it's stale. Never raises -- if both
    the cache and the network are unavailable, whoisit.is_bootstrapped()
    will simply stay False and get_domain_age() reports 'unknown'.
    """
    if whoisit.is_bootstrapped():
        return

    cached = None
    try:
        with open(BOOTSTRAP_CACHE_PATH, 'r', encoding='utf-8') as f:
            cached = f.read()
        whoisit.load_bootstrap_data(cached, overrides=True)
    except Exception:
        cached = None

    if cached is not None and not whoisit.bootstrap_is_older_than(BOOTSTRAP_MAX_AGE_DAYS):
        return  # cache is loaded and fresh enough

    try:
        whoisit.clear_bootstrapping()
        whoisit.bootstrap(overrides=True)
        os.makedirs(os.path.dirname(BOOTSTRAP_CACHE_PATH), exist_ok=True)
        with open(BOOTSTRAP_CACHE_PATH, 'w', encoding='utf-8') as f:
            f.write(whoisit.save_bootstrap_data())
    except Exception:
        # Live refresh failed -- fall back to the cache we already had
        # (even if stale) rather than ending up with no bootstrap data.
        if cached is not None:
            try:
                whoisit.load_bootstrap_data(cached, overrides=True)
            except Exception:
                pass


def get_domain_age(domain: str) -> dict:
    """
    Look up the RDAP registration date for a domain and compute its age.

    Returns a dict:
        {
            'age_days'      : int | None,   # None if we couldn't determine age
            'creation_date' : str | None,   # ISO date string of registration
            'registrar'     : str | None,   # Registrar name if available
            'detail'        : str,          # Human-readable summary
        }
    """
    _ensure_bootstrapped()

    if not whoisit.is_bootstrapped():
        return {
            'age_days': None, 'creation_date': None, 'registrar': None,
            'detail': f'RDAP bootstrap data unavailable for "{domain}" (no cache and no network).',
        }

    try:
        result = whoisit.domain(domain)
    except Exception as e:
        # RDAP can fail for many reasons: unsupported TLD, domain not found,
        # rate limiting, network errors. Treat as inconclusive, never crash.
        short_msg = str(e).splitlines()[0][:120]
        return {
            'age_days': None, 'creation_date': None, 'registrar': None,
            'detail': f'RDAP lookup failed for "{domain}": {type(e).__name__} -- {short_msg}',
        }

    creation = result.get('registration_date')
    if creation is None:
        return {
            'age_days': None, 'creation_date': None,
            'registrar': _safe_registrar(result),
            'detail': f'RDAP returned no registration date for "{domain}" (privacy redaction or unsupported field).',
        }

    # whoisit returns timezone-aware datetimes, but normalize defensively
    # in case a registry's RDAP server omits the offset.
    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)

    now = datetime.now(tz=timezone.utc)
    age_days = (now - creation).days

    creation_str = creation.strftime('%Y-%m-%d')
    registrar = _safe_registrar(result)

    if age_days < 30:
        age_label = f'{age_days} days old -- VERY NEW (critical red flag)'
    elif age_days < 180:
        age_label = f'{age_days} days old -- relatively new (yellow flag)'
    elif age_days < 730:
        age_label = f'{age_days} days old (~{age_days // 30} months)'
    else:
        years = age_days / 365
        age_label = f'{age_days} days old (~{years:.1f} years) -- established domain'

    detail = f'Domain registered {creation_str} ({age_label}).'
    if registrar:
        detail += f' Registrar: {registrar}.'

    return {
        'age_days': age_days,
        'creation_date': creation_str,
        'registrar': registrar,
        'detail': detail,
    }


def _safe_registrar(result: dict) -> str | None:
    """
    Safely extract the registrar name from a whoisit domain() result.
    Entities are keyed by role (e.g. 'registrar', 'registrant', 'abuse'),
    each a list of entity dicts -- absent or empty for many domains.
    """
    entities = result.get('entities') or {}
    registrar_entities = entities.get('registrar') or []
    if not registrar_entities:
        return None
    name = registrar_entities[0].get('name')
    return name.strip() if name else None
