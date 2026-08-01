"""
checks/content.py
------------------
Heuristic analysis of the email BODY text (not headers, not the sender
domain). Scam job offers use predictable language patterns regardless of
how convincing the sender domain looks: upfront payment requests, premature
requests for sensitive personal info, pressure to move off official
channels, manufactured urgency, and "you're hired, no interview needed"
phrasing.

All checks here are offline keyword/regex matching against the pasted body
text -- no network calls, no LLM, nothing that leaves the machine. This is
deliberately the same "never crash, degrade gracefully" philosophy as the
rest of the checks/ package, though there's nothing here that can really
fail except an empty string.

Each sub-check returns:
    {
        'detected': bool,          # True if the pattern was found
        'matches':  list[str],     # the phrases/patterns that triggered it
        'detail':   str,           # human-readable summary
    }

analyze_email_body() is only meant to be called when the user actually
pasted body text -- same optionality as the raw-header checks in header.py.
"""

import re


def _find_matches(body: str, phrases: list[str]) -> list[str]:
    """
    Return the subset of `phrases` found in `body`, case-insensitive,
    matched on word boundaries so short phrases (like "ssn") don't fire on
    unrelated substrings inside longer words.
    """
    lower = body.lower()
    return [p for p in phrases if re.search(r'\b' + re.escape(p) + r'\b', lower)]


# ---------------------------------------------------------------------------
# Upfront payment / fee request
# One of the single strongest scam signals: legitimate employers never ask
# a candidate to pay for their own onboarding, equipment, or "training".
# ---------------------------------------------------------------------------
UPFRONT_PAYMENT_PHRASES = [
    'processing fee', 'registration fee', 'application fee', 'training fee',
    'purchase your own equipment', 'starter kit', 'cash this check',
    'cash the check', 'wire transfer', 'gift card', 'gift cards',
    'bitcoin', 'cryptocurrency', 'western union', 'moneygram',
    'send back the difference', 'reimburse you after',
]


def check_upfront_payment_request(body: str) -> dict:
    matches = _find_matches(body, UPFRONT_PAYMENT_PHRASES)
    detected = bool(matches)
    detail = (
        f'Body requests payment or money movement upfront: {", ".join(matches)}.'
        if detected else
        'No upfront payment or fee requests found in the body text.'
    )
    return {'detected': detected, 'matches': matches, 'detail': detail}


# ---------------------------------------------------------------------------
# Premature request for sensitive personal/financial info
# Legitimate onboarding collects this through a secure HR portal after a
# signed offer -- not by plain email early in the conversation.
# ---------------------------------------------------------------------------
PREMATURE_PII_PHRASES = [
    'social security number', 'ssn', 'bank account number', 'routing number',
    "copy of your driver's license", 'copy of your passport',
    'date of birth', 'direct deposit information', 'bank statement',
]


def check_premature_pii_request(body: str) -> dict:
    matches = _find_matches(body, PREMATURE_PII_PHRASES)
    detected = bool(matches)
    detail = (
        f'Body asks for sensitive personal or financial info before any '
        f'formal hiring step: {", ".join(matches)}.'
        if detected else
        'No requests for sensitive personal or financial information found.'
    )
    return {'detected': detected, 'matches': matches, 'detail': detail}


# ---------------------------------------------------------------------------
# Push to move communication off official/company channels
# ---------------------------------------------------------------------------
OFFPLATFORM_PHRASES = [
    'whatsapp', 'telegram', 'signal app', 'text me at', 'hangouts',
    'message me on', 'contact me directly at',
]


def check_offplatform_comms(body: str) -> dict:
    matches = _find_matches(body, OFFPLATFORM_PHRASES)
    detected = bool(matches)
    detail = (
        f'Body pushes communication to an unofficial channel: {", ".join(matches)}.'
        if detected else
        'No push to move communication to an unofficial channel found.'
    )
    return {'detected': detected, 'matches': matches, 'detail': detail}


# ---------------------------------------------------------------------------
# Manufactured urgency / pressure language
# Weak signal alone (legitimate marketing uses some of this too), but
# meaningful in combination with the other checks here.
# ---------------------------------------------------------------------------
URGENCY_PHRASES = [
    'act now', 'act immediately', 'immediately', 'urgent', 'right away',
    'within 24 hours', 'within 12 hours', 'offer expires', 'limited time',
    'start tomorrow', 'today only', "before it's too late", 'asap',
]


def check_urgency_language(body: str) -> dict:
    matches = _find_matches(body, URGENCY_PHRASES)
    detected = bool(matches)
    detail = (
        f'Body uses urgency/pressure language: {", ".join(matches)}.'
        if detected else
        'No notable urgency or pressure language found.'
    )
    return {'detected': detected, 'matches': matches, 'detail': detail}


# ---------------------------------------------------------------------------
# Instant hire / no interview
# Real hiring involves some form of vetting; skipping straight to "you're
# hired" off a resume alone is a classic scam shortcut.
# ---------------------------------------------------------------------------
INSTANT_HIRE_PHRASES = [
    'you are hired', 'you have been hired', 'no interview necessary',
    'no interview is required', 'approved based on your resume',
    'congratulations, you are hired', 'hired immediately',
]


def check_instant_hire(body: str) -> dict:
    matches = _find_matches(body, INSTANT_HIRE_PHRASES)
    detected = bool(matches)
    detail = (
        f'Body claims an offer/hire with no interview process: {", ".join(matches)}.'
        if detected else
        'No instant-hire / no-interview claims found.'
    )
    return {'detected': detected, 'matches': matches, 'detail': detail}


# ---------------------------------------------------------------------------
# Generic, non-personalized greeting
# Weakest signal here -- some legitimate automated systems do this too --
# but it's consistent with a message blasted to many recipients at once.
# ---------------------------------------------------------------------------
GENERIC_GREETING_PATTERNS = [
    r'dear applicant', r'dear candidate', r'dear job seeker',
    r'to whom it may concern', r'dear sir\s*/?\s*(or\s*)?madam',
]


def check_generic_greeting(body: str) -> dict:
    lower = body.lower()
    matches = [p for p in GENERIC_GREETING_PATTERNS if re.search(p, lower)]
    detected = bool(matches)
    detail = (
        'Body opens with a generic, non-personalized greeting '
        '(often a sign of a mass-sent message).'
        if detected else
        'No generic/impersonal greeting pattern found.'
    )
    return {'detected': detected, 'matches': matches, 'detail': detail}


def analyze_email_body(body: str) -> dict:
    """
    Run all body-language heuristics and return a dict of sub-check results,
    keyed by check name. Only call this when the user actually supplied
    body text -- there's nothing meaningful to check in an empty string.
    """
    return {
        'upfront_payment':   check_upfront_payment_request(body),
        'premature_pii':     check_premature_pii_request(body),
        'offplatform_comms': check_offplatform_comms(body),
        'urgency_language':  check_urgency_language(body),
        'instant_hire':      check_instant_hire(body),
        'generic_greeting':  check_generic_greeting(body),
    }
