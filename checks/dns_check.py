"""
checks/dns_check.py
-------------------
DNS-based legitimacy checks for an email sender's domain.

We look for three types of records that all reputable email senders configure:

  MX  — Mail Exchange records: proves the domain is set up to send/receive email.
         A domain without MX records almost certainly didn't originate the email.

  SPF — Sender Policy Framework (a TXT record starting with "v=spf1"):
         Declares which servers are allowed to send email for this domain.
         Absence doesn't guarantee fraud, but it's a yellow flag.

  DMARC — Domain-based Message Authentication, Reporting & Conformance
           (a TXT record at _dmarc.<domain>): tells receiving servers what to do
           when SPF/DKIM checks fail. Large organisations almost always have this.
           Its absence combined with other flags raises suspicion.

All functions:
  - Return a dict with a 'found' boolean and a 'detail' string.
  - Catch DNS exceptions and return a "could not verify" result rather than
    crashing, because DNS queries can time out, be blocked by firewalls, etc.
"""

import dns.resolver
import dns.exception


# Timeout in seconds for each DNS query.
# 5 seconds is generous enough for slow resolvers but short enough that
# a single check doesn't make the tool feel broken.
DNS_TIMEOUT = 5


def _make_resolver() -> dns.resolver.Resolver:
    """
    Create a dns.resolver.Resolver with our preferred timeout.
    We build a fresh resolver each call so parallel calls don't share state.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT   # total time for all retries
    resolver.timeout  = DNS_TIMEOUT   # per-query timeout
    return resolver


def check_mx_records(domain: str) -> dict:
    """
    Check whether the domain has MX (Mail Exchange) records.

    MX records are required for a domain to send or receive email properly.
    A legitimate company's domain will always have them.
    A freshly registered scam domain often skips this configuration step,
    or the scammer registered a domain purely for display purposes.

    Returns:
        {
            'found':  bool,   # True if at least one MX record exists
            'detail': str,    # human-readable explanation
        }
    """
    resolver = _make_resolver()
    try:
        answers = resolver.resolve(domain, 'MX')
        # Pull out the mail server hostnames for the detail message
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        return {
            'found': True,
            'detail': f'MX records found: {", ".join(mx_hosts[:3])}'
                      + (' (and more)' if len(mx_hosts) > 3 else ''),
        }
    except dns.resolver.NXDOMAIN:
        # The domain doesn't exist at all — very suspicious
        return {
            'found': False,
            'detail': f'Domain "{domain}" does not exist (NXDOMAIN).',
        }
    except dns.resolver.NoAnswer:
        # Domain exists but has no MX records
        return {
            'found': False,
            'detail': f'No MX records found for "{domain}".',
        }
    except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception) as e:
        # DNS query failed — we can't draw a conclusion, so we note it
        return {
            'found': None,   # None = unknown/inconclusive
            'detail': f'MX lookup failed (network issue or timeout): {type(e).__name__}',
        }


def check_spf_record(domain: str) -> dict:
    """
    Check whether the domain publishes an SPF record.

    SPF is a TXT record at the domain's root that starts with "v=spf1".
    It tells receiving mail servers which IP addresses are authorised to
    send email claiming to be from this domain.

    A missing SPF record doesn't prove fraud — small domains sometimes
    omit it — but its absence combined with other red flags is meaningful.

    Returns:
        {
            'found':  bool | None,  # True=found, False=not found, None=error
            'record': str | None,   # the actual SPF string if found
            'detail': str,
        }
    """
    resolver = _make_resolver()
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            # TXT records can have multiple strings; join them and check for SPF
            txt_value = ''.join(s.decode('utf-8', errors='replace')
                                for s in rdata.strings)
            if txt_value.startswith('v=spf1'):
                return {
                    'found': True,
                    'record': txt_value,
                    'detail': f'SPF record found: {txt_value[:80]}'
                              + ('…' if len(txt_value) > 80 else ''),
                }
        # TXT records exist but none is an SPF record
        return {
            'found': False,
            'record': None,
            'detail': f'No SPF record found for "{domain}" (TXT records exist but none starts with "v=spf1").',
        }
    except dns.resolver.NXDOMAIN:
        return {
            'found': False,
            'record': None,
            'detail': f'Domain "{domain}" does not exist (NXDOMAIN).',
        }
    except dns.resolver.NoAnswer:
        return {
            'found': False,
            'record': None,
            'detail': f'No TXT records found for "{domain}", so no SPF record.',
        }
    except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception) as e:
        return {
            'found': None,
            'record': None,
            'detail': f'SPF lookup failed (network issue or timeout): {type(e).__name__}',
        }


def check_dmarc_record(domain: str) -> dict:
    """
    Check whether the domain publishes a DMARC policy.

    DMARC lives at the DNS name "_dmarc.<domain>" as a TXT record starting
    with "v=DMARC1". It instructs receiving servers how to handle mail that
    fails SPF or DKIM authentication (quarantine, reject, or do nothing).

    Large organisations almost universally publish DMARC records.
    Scam domains almost never do — setting up DMARC requires intent to manage
    email infrastructure properly, which fly-by-night operations skip.

    Returns:
        {
            'found':  bool | None,
            'record': str | None,
            'detail': str,
        }
    """
    resolver = _make_resolver()
    # DMARC records live at a special subdomain of the target domain
    dmarc_domain = f'_dmarc.{domain}'
    try:
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_value = ''.join(s.decode('utf-8', errors='replace')
                                for s in rdata.strings)
            if txt_value.startswith('v=DMARC1'):
                return {
                    'found': True,
                    'record': txt_value,
                    'detail': f'DMARC record found: {txt_value[:80]}'
                              + ('…' if len(txt_value) > 80 else ''),
                }
        return {
            'found': False,
            'record': None,
            'detail': f'No DMARC record found at "{dmarc_domain}".',
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            'found': False,
            'record': None,
            'detail': f'No DMARC record found at "{dmarc_domain}".',
        }
    except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception) as e:
        return {
            'found': None,
            'record': None,
            'detail': f'DMARC lookup failed (network issue or timeout): {type(e).__name__}',
        }
