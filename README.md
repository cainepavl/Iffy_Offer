# BS_DTect — Job Offer Email Legitimacy Checker

A desktop tool that analyses a job-offer email and estimates whether it's from
a legitimate company or a phishing/scam attempt.

Enter the company name and the sender's email address (and optionally paste the
raw email headers), click **Analyze**, and get a risk verdict in seconds.

---

## Features

- **Domain analysis** — detects homoglyph substitutions (`amaz0n.com`) and
  typosquatted domains (`amzon-careers.com`)
- **Free-provider detection** — flags addresses from Gmail, Yahoo, Hotmail, etc.
- **ATS platform recognition** — recognises legitimate recruiting platforms
  (Greenhouse, Workday, Lever, LinkedIn, etc.)
- **Domain age check** — WHOIS lookup flags brand-new domains (< 30 days)
- **DNS record checks** — verifies MX, SPF, and DMARC records
- **Header analysis** — detects display-name spoofing and Reply-To hijacking
  (when raw headers are provided)
- **Risk score** — all signals combine into a single score with a colour-coded verdict
- **Dark & light mode** — toggle with one click

---

## Screenshots

> *(Add screenshots here once the app is running)*

---

## Installation

**Requirements:** Python 3.10 or newer

```bash
git clone https://github.com/your-username/BS_DTect.git
cd BS_DTect
pip install -r requirements.txt
python main.py
```

Tkinter comes with the Python standard library. On some Linux systems you may
need to install it separately:

```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter
```

---

## Usage

1. **Company Name** — type the name of the company that supposedly sent the email
   (e.g. `Amazon`, `Google`, `Acme Corp`)

2. **Sender Email** — paste the *full* From address, including display name if shown
   (e.g. `Amazon Recruiting <hr@amaz0n-careers.net>`)

3. **Raw Headers** *(optional)* — in your email client, choose "Show Original" or
   "View Source" and paste the full header block into the text area.
   This enables display-name spoofing and Reply-To mismatch checks.

4. Click **Analyze Email** and wait a few seconds for DNS/WHOIS lookups to complete.

---

## Finding the Raw Header Block

The raw header block is the machine-readable metadata that sits above the email
body. Every email has one; it's just hidden by default.

### How to open it in common clients

| Client              | Steps                                                                                                |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| **Gmail** (web)     | Open the email → click the **⋮** (three-dot) menu at the top right → **Show original**             |
| **Outlook** (web)   | Open the email → click **⋯** → **View** → **View message source**                                  |
| **Outlook** (desktop) | Open the email in its own window → **File** → **Properties** → look in the *Internet headers* box |
| **Apple Mail**      | Open the email → **View** menu → **Message** → **Raw Source**                                       |
| **Thunderbird**     | Open the email → **View** menu → **Message Source** (or `Ctrl+U`)                                   |
| **Yahoo Mail**      | Open the email → click the **⋯** menu → **View Raw Message**                                        |

### What to copy

Once the raw source is open you will see something like this at the very top:

```text
Delivered-To: you@example.com
Received: from mail.sender.com ...
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.com;
        h=from:to:subject:date; bh=...; b=...
From: "HR Team" <hr@sender.com>
To: you@example.com
Subject: Exciting Opportunity
Date: Fri, 06 Jun 2026 10:00:00 +0000
Reply-To: different@otherdomain.com
...
```

Copy everything from the **very first line** down to (but not including) the blank
line that separates the headers from the email body. Paste that block into the
**Raw Headers** field in BS_DTect.

> **Tip:** The header block always ends at the first completely blank line. Everything
> after that blank line is the body of the email — you don't need it.

---

## How Scoring Works

Each check contributes a signed integer delta to a cumulative risk score.

| Check                            | Score delta |
| -------------------------------- | :---------: |
| Free email provider (gmail, etc) |    –40      |
| Known ATS / recruiter platform   |    +20      |
| Homoglyph characters in domain   |    –30      |
| Typosquatting detected           |    –25      |
| Domain < 30 days old             |    –30      |
| Domain 30–180 days old           |    –15      |
| Domain > 2 years old             |    +10      |
| No MX records                    |    –20      |
| No SPF record                    |    –10      |
| No DMARC record                  |    –10      |
| Reply-To domain mismatch         |    –20      |
| Display name spoofing            |    –15      |

**Verdict bands:**

| Score      | Verdict        |
| ---------- | -------------- |
| ≥ 0        | 🟢 LOW RISK    |
| –1 to –29  | 🟡 MEDIUM RISK |
| ≤ –30      | 🔴 HIGH RISK   |

---

## What This Tool Does NOT Do

- **Does not open, scan, or execute attachments** — attachment inspection would
  require sandboxing that is beyond this tool's scope.
- **Does not follow or analyse links** in the email body.
- **Does not contact the company** to verify the recruiter's identity.
- **Cannot guarantee accuracy** — a well-resourced attacker can pass some of
  these checks (e.g. by setting up SPF/DMARC on a fake domain). Use this tool
  as one input among several, not as a definitive verdict.

---

## Limitations

- WHOIS lookups can fail for some TLDs (privacy shields, unsupported registries).
  The tool will show "unknown" for age rather than error out.
- DNS checks require an internet connection.
- The ATS platform and free-provider lists are curated manually — they may not
  cover every service.

---

## Extending

To add a new free provider or ATS platform, just add a line to
`data/free_providers.txt` or `data/ats_platforms.txt`. No code changes required.

To add a new check, see the **Adding a New Check** section in `CLAUDE.md`.

---

## License

MIT — see `LICENSE` for details.

---

## Disclaimer

This tool is provided for **educational and personal use only**. It does not
constitute legal, security, or professional advice. Always verify suspicious
emails through official channels before taking action.
