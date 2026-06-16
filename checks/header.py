"""
checks/header.py
----------------
Parses raw email header text to detect common spoofing indicators.

Email headers tell the story of how a message travelled from sender to inbox.
Scammers often manipulate headers to make a message *look* like it comes from
a legitimate company while routing replies somewhere entirely different.

We look for two main red flags (without requiring DKIM/DMARC validation,
which needs the actual cryptographic keys):

  1. Display name spoofing:
     The "From" header can contain a friendly name AND an email address, e.g.:
       From: Amazon HR <hr@totally-fake-domain.com>
     The display name says "Amazon HR" but the real sending address is different.
     We compare the display name against the actual domain to flag mismatches.

  2. Reply-To hijacking:
     If a "Reply-To" header is present and its domain differs from the "From"
     domain, replies will go to a different address than the apparent sender.
     Legitimate companies rarely need this; scammers use it to collect replies
     without exposing their actual infrastructure.

Input: raw header text (the block of "Key: Value" lines at the top of an email).
       Most email clients let you view this via "Show Original" or "View Source".
"""

import email
import re
from email.headerregistry import Address


def parse_headers(raw_header_text: str) -> dict:
    """
    Parse a raw email header block and extract key fields.

    We use Python's stdlib `email` module which correctly handles multi-line
    (folded) headers, encoded words (=?UTF-8?...?=), and other RFC 2822 quirks.

    Returns a dict:
        {
            'from_display'  : str | None,   # display name in From header
            'from_address'  : str | None,   # actual email address in From header
            'from_domain'   : str | None,   # domain of the actual From address
            'reply_to'      : str | None,   # Reply-To address if present
            'reply_to_domain': str | None,  # domain of Reply-To if present
            'subject'       : str | None,
            'date'          : str | None,
            'received_count': int,          # number of "Received:" hops
            'parse_error'   : bool,         # True if parsing failed
        }
    """
    if not raw_header_text or not raw_header_text.strip():
        return _empty_result(parse_error=True)

    try:
        # The email module expects a full message; we fake a body with \n\n
        # so it parses just the header block correctly.
        msg = email.message_from_string(raw_header_text.strip() + '\n\n')
    except Exception:
        return _empty_result(parse_error=True)

    from_raw     = msg.get('From', '')
    reply_to_raw = msg.get('Reply-To', '')

    from_display, from_address = _parse_address_field(from_raw)
    from_domain   = _extract_domain(from_address)

    _, reply_to_address = _parse_address_field(reply_to_raw)
    reply_to_domain      = _extract_domain(reply_to_address) if reply_to_address else None

    # Count Received: headers — each one represents a server hop.
    # An unusually long chain (10+) can indicate message laundering, though
    # this is a weak signal and we don't penalise it directly.
    received_count = sum(1 for k in msg.keys() if k.lower() == 'received')

    return {
        'from_display'   : from_display,
        'from_address'   : from_address,
        'from_domain'    : from_domain,
        'reply_to'       : reply_to_address,
        'reply_to_domain': reply_to_domain,
        'subject'        : msg.get('Subject'),
        'date'           : msg.get('Date'),
        'received_count' : received_count,
        'parse_error'    : False,
    }


def check_display_name_mismatch(parsed: dict, company_name: str) -> dict:
    """
    Detect when the From display name claims to be from the company but the
    actual sending domain doesn't match.

    Example of this attack:
        From: Amazon Recruiting <jobs@xn--amzon-q17b.com>
    The display name says "Amazon Recruiting" but the domain is a lookalike.

    We check if any significant word from the company name appears in the
    display name, and if so, whether the sending domain seems related.

    Returns:
        {
            'mismatch': bool,   # True = suspicious display name vs domain
            'detail'  : str,
        }
    """
    if parsed.get('parse_error') or not parsed.get('from_display'):
        return {'mismatch': False, 'detail': 'No display name to analyse.'}

    display = parsed['from_display'].lower()
    domain  = parsed.get('from_domain', '').lower()
    company = company_name.lower()

    # Strip company stop-words for a cleaner comparison
    stop_words = {'inc', 'llc', 'corp', 'ltd', 'co', 'the', 'and', 'group'}
    company_tokens = [
        t for t in re.split(r'\W+', company)
        if len(t) > 2 and t not in stop_words
    ]

    # Check if the display name contains a company keyword
    company_in_display = any(tok in display for tok in company_tokens)

    if not company_in_display:
        # Display name doesn't claim to be from this company — no mismatch
        return {
            'mismatch': False,
            'detail': 'Display name does not reference the claimed company.',
        }

    # If the display name DOES mention the company, check whether the domain
    # also looks related (i.e., contains a company keyword)
    domain_looks_related = any(tok in domain for tok in company_tokens)

    if not domain_looks_related:
        return {
            'mismatch': True,
            'detail': (
                f'Display name "{parsed["from_display"]}" references "{company_name}" '
                f'but the actual sending domain "{domain}" does not appear related. '
                f'This is a common display-name spoofing tactic.'
            ),
        }

    return {
        'mismatch': False,
        'detail': (
            f'Display name "{parsed["from_display"]}" and domain "{domain}" '
            f'both appear to reference "{company_name}".'
        ),
    }


def check_reply_to_mismatch(parsed: dict) -> dict:
    """
    Detect when the Reply-To domain differs from the From domain.

    If you reply to an email, your client sends it to the Reply-To address,
    not the From address. Scammers use this to:
      - Collect replies on infrastructure they control (often a throwaway inbox)
      - Keep their real sending server hidden

    Legitimate companies occasionally use Reply-To for mailing lists or
    automated systems, but a mismatch in conjunction with other flags is a
    meaningful warning.

    Returns:
        {
            'mismatch': bool,
            'detail'  : str,
        }
    """
    if parsed.get('parse_error'):
        return {'mismatch': False, 'detail': 'Headers could not be parsed.'}

    from_domain    = parsed.get('from_domain')
    reply_to_domain = parsed.get('reply_to_domain')

    if not reply_to_domain:
        # No Reply-To header — completely normal, nothing to flag
        return {
            'mismatch': False,
            'detail': 'No Reply-To header present (normal).',
        }

    if not from_domain:
        return {
            'mismatch': False,
            'detail': 'Could not determine From domain to compare against Reply-To.',
        }

    if from_domain != reply_to_domain:
        return {
            'mismatch': True,
            'detail': (
                f'Reply-To domain "{reply_to_domain}" differs from '
                f'From domain "{from_domain}". Replies will go to a '
                f'different server than the apparent sender.'
            ),
        }

    return {
        'mismatch': False,
        'detail': f'Reply-To domain matches From domain ("{from_domain}").',
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_address_field(raw: str) -> tuple[str | None, str | None]:
    """
    Split a raw From/Reply-To field into (display_name, email_address).

    Handles formats like:
        "Amazon HR <hr@amazon.com>"   → ("Amazon HR", "hr@amazon.com")
        "hr@amazon.com"               → (None, "hr@amazon.com")
        ""                            → (None, None)
    """
    if not raw or not raw.strip():
        return None, None

    # Try the angle-bracket format first: "Display Name <email@domain.com>"
    angle_match = re.match(r'^(.+?)\s*<([^>]+)>\s*$', raw.strip())
    if angle_match:
        display = angle_match.group(1).strip().strip('"').strip("'")
        address = angle_match.group(2).strip()
        return (display or None, address or None)

    # Otherwise, treat the whole thing as a bare email address
    raw = raw.strip()
    if '@' in raw:
        return None, raw

    return None, None


def _extract_domain(email_address: str | None) -> str | None:
    """Extract the domain from a plain email address string."""
    if not email_address or '@' not in email_address:
        return None
    return email_address.rsplit('@', 1)[1].lower()


def _empty_result(parse_error: bool = False) -> dict:
    """Return a zeroed-out result dict for when we have no header data."""
    return {
        'from_display'   : None,
        'from_address'   : None,
        'from_domain'    : None,
        'reply_to'       : None,
        'reply_to_domain': None,
        'subject'        : None,
        'date'           : None,
        'received_count' : 0,
        'parse_error'    : parse_error,
    }
