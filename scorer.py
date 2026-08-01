"""
scorer.py
---------
Aggregates the results from all individual checks into a single risk score
and a human-readable verdict.

Scoring philosophy:
  - Each check returns a signed integer delta (negative = suspicious).
  - Checks that can't run (DNS timeout, WHOIS blocked, etc.) contribute 0
    but are noted as "inconclusive" in the output.
  - The final score maps to one of three verdict bands.

Verdict bands (chosen to mirror real-world email risk tooling conventions):
  Score ≥  0  →  Looks Legit  (green)  — No significant red flags found.
  Score –1 to –29  →  Iffy         (yellow) — Some concerns; verify independently.
  Score ≤ –30  →  Yikes!       (red)   — Multiple red flags; treat as probable scam.

Score deltas (all negative values mean "more suspicious"):

  Free email provider   : –40   Large penalty. Real companies don't recruit from gmail.
  Known ATS platform    : +20   Positive signal. These are trusted recruitment tools.
  Domain < 30 days      : –30   Extremely suspicious. New domains = burner domain.
  Domain 30–180 days    : –15   Somewhat suspicious. Young for a recruiting domain.
  Domain > 2 years      : +10   Mild positive. Established domains are harder to fake.
  No MX records         : –20   The domain can't properly handle email.
  No SPF record         : –10   Standard configuration missing.
  No DMARC record       : –10   Standard configuration missing.
  Fuzzy domain match    : –25   Likely typosquatting.
  Homoglyph detected    : –30   Deliberate visual deception — very serious.
  Reply-To mismatch     : –20   Replies are redirected away from sender.
  Display name mismatch : –15   Display name spoofing.

  Body: upfront payment request   : –35   One of the strongest scam signals.
  Body: premature PII/financial   : –25   Sensitive info asked for too early.
  Body: instant hire, no interview: –15   Real hiring involves some vetting.
  Body: off-platform comms push   : –15   Pushed off official channels.
  Body: urgency/pressure language : –10   Weak alone, meaningful combined.
  Body: generic greeting          : –5    Weakest signal; mass-sent messages.

  Attachment: dangerous extension     : –35   Executable/script attachment.
  Attachment: signature mismatch      : –30   Content doesn't match extension.
  Attachment: archive has executable  : –30   Filter-bypass trick.
  Attachment: macros, high risk       : –40   Auto-exec + suspicious API use.
  Attachment: macros, medium risk     : –25   Auto-exec or suspicious API use.
  Attachment: macros, low risk        : –15   Macros present, nothing flagged.
  Attachment: PDF embedded action/JS  : –25   Embedded script or auto-launch.
  Attachment: disk-image container    : –20   Known malware-delivery pattern.
"""

from dataclasses import dataclass, field


@dataclass
class CheckResult:
    """
    Represents the outcome of a single check.

    Fields:
        name    — short label shown in the results panel (e.g. "SPF Record")
        status  — one of: 'ok', 'warning', 'fail', 'info', 'unknown'
        detail  — one-line explanation shown to the user
        delta   — score contribution (negative = riskier, 0 = neutral)
    """
    name:   str
    status: str          # 'ok' | 'warning' | 'fail' | 'info' | 'unknown'
    detail: str
    delta:  int = 0      # default to 0 (no score impact) for informational checks


@dataclass
class ScorerOutput:
    """
    The complete output from the scorer: a list of individual results,
    a total score, and a verdict string with associated color category.
    """
    results: list = field(default_factory=list)   # list of CheckResult
    score:   int  = 0
    verdict: str  = ''     # 'Looks Legit' | 'Iffy' | 'Yikes!'
    color:   str  = ''     # 'green'   | 'yellow'       | 'red'


def build_score(
    domain:            str,
    company_name:      str,
    free_provider:     bool,
    ats_platform:      bool,
    domain_info:       dict,   # from checks.domain.check_domain_vs_company()
    whois_info:        dict,   # from checks.whois_check.get_domain_age()
    mx_info:           dict,   # from checks.dns_check.check_mx_records()
    spf_info:          dict,   # from checks.dns_check.check_spf_record()
    dmarc_info:        dict,   # from checks.dns_check.check_dmarc_record()
    display_mismatch:  dict | None = None,  # from checks.header.check_display_name_mismatch()
    reply_to_mismatch: dict | None = None,  # from checks.header.check_reply_to_mismatch()
    body_info:         dict | None = None,  # from checks.content.analyze_email_body()
    attachment_info:   dict | None = None,  # from checks.attachment.analyze_attachment()
) -> ScorerOutput:
    """
    Combine all check results into a ScorerOutput with total score and verdict.

    Each check is evaluated in turn, contributing a delta and a CheckResult
    entry. Inconclusive checks (where the tool couldn't fetch data) contribute
    0 to the score but are displayed as 'unknown' for transparency.
    """
    results = []
    score   = 0

    # ------------------------------------------------------------------
    # 1. Free email provider check
    # ------------------------------------------------------------------
    if free_provider:
        delta = -40
        results.append(CheckResult(
            name='Free Email Provider',
            status='fail',
            detail=f'"{domain}" is a free/consumer email provider. '
                   f'Legitimate companies do not recruit from these.',
            delta=delta,
        ))
    else:
        delta = 0
        results.append(CheckResult(
            name='Free Email Provider',
            status='ok',
            detail=f'"{domain}" is not a known free email provider.',
            delta=0,
        ))
    score += delta

    # ------------------------------------------------------------------
    # 2. Known ATS / recruitment platform check
    # ------------------------------------------------------------------
    if ats_platform:
        delta = +20
        results.append(CheckResult(
            name='ATS / Recruiter Platform',
            status='ok',
            detail=f'"{domain}" is a known recruitment platform (ATS). '
                   f'Many legitimate companies send via these services.',
            delta=delta,
        ))
        score += delta
    # No penalty for NOT being an ATS platform — most real company domains won't be

    # ------------------------------------------------------------------
    # 3. Homoglyph detection
    # ------------------------------------------------------------------
    if domain_info.get('homoglyph_detected'):
        delta = -30
        results.append(CheckResult(
            name='Homoglyph Substitution',
            status='fail',
            detail=domain_info.get('detail', 'Homoglyph characters detected in domain.'),
            delta=delta,
        ))
        score += delta
    # ------------------------------------------------------------------
    # 4. Fuzzy domain vs company name match (only if no homoglyphs — they're
    #    already captured above and we don't want to double-penalise)
    # ------------------------------------------------------------------
    elif domain_info.get('fuzzy_match'):
        delta = -25
        results.append(CheckResult(
            name='Typosquatting Detection',
            status='fail',
            detail=domain_info.get('detail', 'Domain is suspiciously similar to company name.'),
            delta=delta,
        ))
        score += delta
    else:
        # Domain doesn't seem to impersonate the company
        results.append(CheckResult(
            name='Domain vs Company Name',
            status='ok',
            detail=domain_info.get('detail', 'Domain does not appear to impersonate the company.'),
            delta=0,
        ))

    # ------------------------------------------------------------------
    # 5. Domain age (WHOIS)
    # ------------------------------------------------------------------
    age_days = whois_info.get('age_days')
    if age_days is None:
        # WHOIS lookup failed or was blocked — report but don't penalise
        results.append(CheckResult(
            name='Domain Age',
            status='unknown',
            detail=whois_info.get('detail', 'Could not determine domain age.'),
            delta=0,
        ))
    elif age_days < 30:
        # Brand new domain — critical red flag
        delta = -30
        results.append(CheckResult(
            name='Domain Age',
            status='fail',
            detail=whois_info.get('detail', f'Domain is only {age_days} days old.'),
            delta=delta,
        ))
        score += delta
    elif age_days < 180:
        # Less than 6 months — moderate concern
        delta = -15
        results.append(CheckResult(
            name='Domain Age',
            status='warning',
            detail=whois_info.get('detail', f'Domain is {age_days} days old.'),
            delta=delta,
        ))
        score += delta
    elif age_days >= 730:
        # Over 2 years — mild positive signal
        delta = +10
        results.append(CheckResult(
            name='Domain Age',
            status='ok',
            detail=whois_info.get('detail', f'Domain is {age_days} days old.'),
            delta=delta,
        ))
        score += delta
    else:
        # 6 months to 2 years — acceptable, no adjustment
        results.append(CheckResult(
            name='Domain Age',
            status='ok',
            detail=whois_info.get('detail', f'Domain is {age_days} days old.'),
            delta=0,
        ))

    # ------------------------------------------------------------------
    # 6. MX records
    # ------------------------------------------------------------------
    mx_found = mx_info.get('found')
    if mx_found is True:
        results.append(CheckResult(
            name='MX Records',
            status='ok',
            detail=mx_info.get('detail', 'MX records found.'),
            delta=0,
        ))
    elif mx_found is False:
        delta = -20
        results.append(CheckResult(
            name='MX Records',
            status='fail',
            detail=mx_info.get('detail', 'No MX records found.'),
            delta=delta,
        ))
        score += delta
    else:
        # mx_found is None → inconclusive
        results.append(CheckResult(
            name='MX Records',
            status='unknown',
            detail=mx_info.get('detail', 'MX lookup inconclusive.'),
            delta=0,
        ))

    # ------------------------------------------------------------------
    # 7. SPF record
    # ------------------------------------------------------------------
    spf_found = spf_info.get('found')
    if spf_found is True:
        results.append(CheckResult(
            name='SPF Record',
            status='ok',
            detail=spf_info.get('detail', 'SPF record found.'),
            delta=0,
        ))
    elif spf_found is False:
        delta = -10
        results.append(CheckResult(
            name='SPF Record',
            status='warning',
            detail=spf_info.get('detail', 'No SPF record found.'),
            delta=delta,
        ))
        score += delta
    else:
        results.append(CheckResult(
            name='SPF Record',
            status='unknown',
            detail=spf_info.get('detail', 'SPF lookup inconclusive.'),
            delta=0,
        ))

    # ------------------------------------------------------------------
    # 8. DMARC record
    # ------------------------------------------------------------------
    dmarc_found = dmarc_info.get('found')
    if dmarc_found is True:
        results.append(CheckResult(
            name='DMARC Record',
            status='ok',
            detail=dmarc_info.get('detail', 'DMARC record found.'),
            delta=0,
        ))
    elif dmarc_found is False:
        delta = -10
        results.append(CheckResult(
            name='DMARC Record',
            status='warning',
            detail=dmarc_info.get('detail', 'No DMARC record found.'),
            delta=delta,
        ))
        score += delta
    else:
        results.append(CheckResult(
            name='DMARC Record',
            status='unknown',
            detail=dmarc_info.get('detail', 'DMARC lookup inconclusive.'),
            delta=0,
        ))

    # ------------------------------------------------------------------
    # 9. Header checks (optional — only run if headers were provided)
    # ------------------------------------------------------------------
    if display_mismatch is not None:
        if display_mismatch.get('mismatch'):
            delta = -15
            results.append(CheckResult(
                name='Display Name Spoofing',
                status='fail',
                detail=display_mismatch.get('detail', 'Display name does not match sending domain.'),
                delta=delta,
            ))
            score += delta
        else:
            results.append(CheckResult(
                name='Display Name',
                status='ok',
                detail=display_mismatch.get('detail', 'Display name consistent with sending domain.'),
                delta=0,
            ))

    if reply_to_mismatch is not None:
        if reply_to_mismatch.get('mismatch'):
            delta = -20
            results.append(CheckResult(
                name='Reply-To Mismatch',
                status='fail',
                detail=reply_to_mismatch.get('detail', 'Reply-To domain differs from From domain.'),
                delta=delta,
            ))
            score += delta
        else:
            results.append(CheckResult(
                name='Reply-To Header',
                status='ok',
                detail=reply_to_mismatch.get('detail', 'Reply-To is consistent or not present.'),
                delta=0,
            ))

    # ------------------------------------------------------------------
    # 10. Body language checks (optional — only run if body text was provided)
    # Each entry: (sub-check key, display name, delta if detected, status if detected)
    # ------------------------------------------------------------------
    if body_info is not None:
        BODY_CHECKS = [
            ('upfront_payment',   'Upfront Payment Request',        -35, 'fail'),
            ('premature_pii',     'Premature PII/Financial Request', -25, 'fail'),
            ('instant_hire',      'Instant Hire / No Interview',     -15, 'warning'),
            ('offplatform_comms', 'Off-Platform Communication Push', -15, 'warning'),
            ('urgency_language',  'Urgency/Pressure Language',       -10, 'warning'),
            ('generic_greeting',  'Generic Greeting',                 -5, 'warning'),
        ]
        for key, name, delta, fail_status in BODY_CHECKS:
            sub = body_info.get(key)
            if sub is None:
                continue
            if sub.get('detected'):
                results.append(CheckResult(name=name, status=fail_status, detail=sub['detail'], delta=delta))
                score += delta
            else:
                results.append(CheckResult(name=name, status='ok', detail=sub['detail'], delta=0))

    # ------------------------------------------------------------------
    # 11. Attachment checks (optional — only run if a file was selected)
    # ------------------------------------------------------------------
    if attachment_info is not None:
        if attachment_info.get('error'):
            results.append(CheckResult(
                name='Attachment Analysis',
                status='unknown',
                detail=attachment_info['error'],
                delta=0,
            ))
        else:
            ATTACHMENT_CHECKS = [
                ('extension_flag',      'Attachment File Type',        -35, 'fail'),
                ('signature_mismatch',  'Attachment Signature Check',  -30, 'fail'),
                ('archive_contents',    'Attachment Archive Contents', -30, 'fail'),
                ('pdf_action_flag',     'Attachment PDF Actions',      -25, 'fail'),
                ('container_flag',      'Attachment Container Type',   -20, 'fail'),
            ]
            for key, name, delta, fail_status in ATTACHMENT_CHECKS:
                sub = attachment_info.get(key)
                if sub is None:
                    continue
                if sub.get('detected') is None:
                    results.append(CheckResult(name=name, status='unknown', detail=sub['detail'], delta=0))
                elif sub.get('detected'):
                    results.append(CheckResult(name=name, status=fail_status, detail=sub['detail'], delta=delta))
                    score += delta
                else:
                    results.append(CheckResult(name=name, status='ok', detail=sub['detail'], delta=0))

            # Macro analysis has three severities instead of a single delta, so
            # it's scored separately rather than through the table above.
            macro = attachment_info.get('macro_analysis')
            if macro is not None:
                if macro.get('detected') is None:
                    results.append(CheckResult(name='Attachment Macros', status='unknown', detail=macro['detail'], delta=0))
                elif not macro.get('detected'):
                    results.append(CheckResult(name='Attachment Macros', status='ok', detail=macro['detail'], delta=0))
                else:
                    severity_delta = {'high': -40, 'medium': -25, 'low': -15}.get(macro.get('severity'), -15)
                    severity_status = 'fail' if severity_delta <= -25 else 'warning'
                    results.append(CheckResult(
                        name='Attachment Macros', status=severity_status,
                        detail=macro['detail'], delta=severity_delta,
                    ))
                    score += severity_delta

    # ------------------------------------------------------------------
    # Final verdict
    # ------------------------------------------------------------------
    if score >= 0:
        verdict = 'Looks Legit'
        color   = 'green'
    elif score >= -29:
        verdict = 'Iffy'
        color   = 'yellow'
    else:
        verdict = 'Yikes!'
        color   = 'red'

    return ScorerOutput(
        results=results,
        score=score,
        verdict=verdict,
        color=color,
    )
