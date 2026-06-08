"""Core fingerprinting engine for WEBRECON.

Pure analysis over an HTTP response (headers + body). No network, stdlib only.

The engine runs a set of declarative signatures against:
  * response headers (case-insensitive)
  * cookie names
  * the response body (regex / substring)

Each matched signature yields a Finding with a category, the detected name, an
optional version, a confidence score and the human-readable evidence that
triggered it. This mirrors the spirit of whatweb / wappalyzer but stays fully
offline and read-only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from email.parser import Parser
from typing import Any, Dict, List, Optional, Pattern, Tuple


@dataclass
class Finding:
    """A single technology detection result."""

    category: str
    name: str
    version: Optional[str] = None
    confidence: int = 50
    evidence: List[str] = field(default_factory=list)

    def merge(self, version: Optional[str], confidence: int, evidence: str) -> None:
        if version and not self.version:
            self.version = version
        self.confidence = max(self.confidence, confidence)
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReconResult:
    """Full result of fingerprinting one response."""

    target: Optional[str] = None
    status: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


# --- signature definitions --------------------------------------------------
#
# Header signatures: (category, name, header-name, value-regex, version-group,
#                     confidence)
# A version-group of None means "presence only".
HEADER_SIGNATURES: List[Tuple[str, str, str, Optional[str], Optional[int], int]] = [
    ("server", "nginx", "server", r"nginx(?:/([\d.]+))?", 1, 90),
    ("server", "Apache", "server", r"apache(?:/([\d.]+))?", 1, 90),
    ("server", "Microsoft-IIS", "server", r"microsoft-iis(?:/([\d.]+))?", 1, 90),
    ("server", "LiteSpeed", "server", r"litespeed", None, 90),
    ("server", "Caddy", "server", r"caddy", None, 85),
    ("server", "gunicorn", "server", r"gunicorn(?:/([\d.]+))?", 1, 85),
    ("server", "Werkzeug", "server", r"werkzeug(?:/([\d.]+))?", 1, 85),
    ("language", "PHP", "x-powered-by", r"php(?:/([\d.]+))?", 1, 90),
    ("language", "ASP.NET", "x-powered-by", r"asp\.net", None, 90),
    ("language", "ASP.NET", "x-aspnet-version", r"([\d.]+)", 1, 95),
    ("framework", "Express", "x-powered-by", r"express", None, 90),
    ("framework", "Next.js", "x-powered-by", r"next\.js", None, 90),
    ("cdn", "Cloudflare", "server", r"cloudflare", None, 95),
    ("cdn", "Cloudflare", "cf-ray", r".", None, 95),
    ("cdn", "Fastly", "x-served-by", r"cache-.*", None, 70),
    ("cdn", "Vercel", "x-vercel-id", r".", None, 90),
    ("cdn", "Amazon CloudFront", "via", r"cloudfront", None, 85),
    ("cdn", "Akamai", "x-akamai-transformed", r".", None, 85),
    ("framework", "Drupal", "x-generator", r"drupal\s*([\d.]+)?", 1, 90),
    ("cms", "Drupal", "x-drupal-cache", r".", None, 90),
    ("server", "Phusion Passenger", "x-powered-by", r"phusion passenger(?:[ /]([\d.]+))?", 1, 85),
    ("security", "HSTS", "strict-transport-security", r".", None, 60),
    ("security", "CSP", "content-security-policy", r".", None, 60),
    ("analytics", "AMP", "amp-cache-transform", r".", None, 60),
]

# Cookie-name signatures: (category, name, cookie-name-regex, confidence)
COOKIE_SIGNATURES: List[Tuple[str, str, str, int]] = [
    ("language", "PHP", r"^PHPSESSID$", 80),
    ("language", "Java", r"^JSESSIONID$", 85),
    ("framework", "ASP.NET", r"^ASP\.NET_SessionId$", 90),
    ("framework", "Laravel", r"^laravel_session$", 90),
    ("framework", "Laravel", r"^XSRF-TOKEN$", 50),
    ("framework", "Django", r"^(csrftoken|sessionid)$", 60),
    ("framework", "Express", r"^connect\.sid$", 80),
    ("cms", "WordPress", r"^wordpress(_logged_in)?_", 85),
    ("cms", "WooCommerce", r"^woocommerce_", 80),
    ("framework", "Ruby on Rails", r"^_.*_session$", 50),
]

# Body signatures: (category, name, body-regex, version-group, confidence)
BODY_SIGNATURES: List[Tuple[str, str, str, Optional[int], int]] = [
    ("cms", "WordPress", r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\s*([\d.]+)?", 1, 95),
    ("cms", "WordPress", r"/wp-content/", None, 80),
    ("cms", "WordPress", r"/wp-includes/", None, 80),
    ("cms", "Joomla", r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla!?\s*([\d.]+)?", 1, 95),
    ("cms", "Joomla", r"/media/jui/", None, 70),
    ("cms", "Drupal", r"<meta[^>]+name=[\"']Generator[\"'][^>]+content=[\"']Drupal\s*([\d.]+)?", 1, 95),
    ("cms", "Ghost", r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Ghost\s*([\d.]+)?", 1, 90),
    ("cms", "Shopify", r"cdn\.shopify\.com", None, 90),
    ("cms", "Wix", r"static\.wixstatic\.com", None, 85),
    ("cms", "Squarespace", r"static1\.squarespace\.com", None, 85),
    ("framework", "React", r"<div[^>]+id=[\"']root[\"']", None, 40),
    ("framework", "React", r"data-reactroot", None, 75),
    ("framework", "Vue.js", r"data-v-[0-9a-f]{8}", None, 60),
    ("framework", "Vue.js", r"<div[^>]+id=[\"']app[\"']", None, 30),
    ("framework", "Angular", r"ng-version=[\"']([\d.]+)?", 1, 85),
    ("framework", "Next.js", r"/_next/static/", None, 85),
    ("framework", "Nuxt.js", r"/_nuxt/", None, 80),
    ("framework", "Gatsby", r"id=[\"']___gatsby[\"']", None, 85),
    ("javascript", "jQuery", r"jquery[.-]([\d.]+)?(?:\.min)?\.js", 1, 80),
    ("javascript", "Bootstrap", r"bootstrap[.-]([\d.]+)?(?:\.min)?\.(?:css|js)", 1, 75),
    ("javascript", "Font Awesome", r"font-?awesome", None, 60),
    ("analytics", "Google Analytics", r"google-analytics\.com/(?:ga|analytics)\.js|gtag\(", None, 80),
    ("analytics", "Google Tag Manager", r"googletagmanager\.com/gtm\.js", None, 85),
]


def _compile(pat: str) -> Pattern[str]:
    return re.compile(pat, re.IGNORECASE)


def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _parse_cookie_names(headers: Dict[str, str]) -> List[str]:
    """Extract cookie names from Set-Cookie / Cookie headers."""
    names: List[str] = []
    for key in ("set-cookie", "cookie"):
        raw = headers.get(key)
        if not raw:
            continue
        # Multiple Set-Cookie folded into one header on newlines.
        for chunk in re.split(r"\n", raw):
            first = chunk.split(";", 1)[0]
            if "=" in first:
                names.append(first.split("=", 1)[0].strip())
    return names


def _upsert(findings: Dict[Tuple[str, str], Finding], category: str, name: str,
            version: Optional[str], confidence: int, evidence: str) -> None:
    key = (category, name)
    existing = findings.get(key)
    if existing is None:
        findings[key] = Finding(
            category=category,
            name=name,
            version=version or None,
            confidence=confidence,
            evidence=[evidence] if evidence else [],
        )
    else:
        existing.merge(version or None, confidence, evidence)


def fingerprint(headers: Optional[Dict[str, str]] = None, body: str = "",
                status: Optional[int] = None, target: Optional[str] = None) -> ReconResult:
    """Fingerprint a response given headers and body. No network access."""
    headers = headers or {}
    norm = _normalize_headers(headers)
    body = body or ""
    findings: Dict[Tuple[str, str], Finding] = {}

    # Header signatures.
    for category, name, hname, vpat, vgrp, conf in HEADER_SIGNATURES:
        hval = norm.get(hname.lower())
        if hval is None:
            continue
        if vpat is None:
            _upsert(findings, category, name, None, conf, f"header {hname}: {hval}")
            continue
        m = _compile(vpat).search(hval)
        if m:
            version = m.group(vgrp) if vgrp and m.lastindex and vgrp <= (m.lastindex or 0) else None
            _upsert(findings, category, name, version, conf, f"header {hname}: {hval}")

    # Cookie signatures.
    cookie_names = _parse_cookie_names(norm)
    for category, name, cpat, conf in COOKIE_SIGNATURES:
        rx = _compile(cpat)
        for cn in cookie_names:
            if rx.search(cn):
                _upsert(findings, category, name, None, conf, f"cookie: {cn}")
                break

    # Body signatures.
    if body:
        for category, name, bpat, vgrp, conf in BODY_SIGNATURES:
            m = _compile(bpat).search(body)
            if m:
                version = m.group(vgrp) if vgrp and m.lastindex and vgrp <= (m.lastindex or 0) else None
                snippet = m.group(0)
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                _upsert(findings, category, name, version, conf, f"body: {snippet}")

        # Generic <meta generator> capture as a low-confidence note.
        gm = _compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)").search(body)
        if gm:
            generator = gm.group(1).strip()
            if not any(f.name.lower() in generator.lower() for f in findings.values()):
                _upsert(findings, "meta", generator, None, 40, f"meta generator: {generator}")

    result = ReconResult(target=target, status=status)
    # Stable, useful ordering: confidence desc, then category, then name.
    result.findings = sorted(
        findings.values(),
        key=lambda f: (-f.confidence, f.category, f.name),
    )
    if not result.findings:
        result.notes.append("no known technologies matched")
    return result


def load_response(text: str) -> Tuple[Dict[str, str], str, Optional[int]]:
    """Parse a raw HTTP response (status line + headers + blank line + body).

    Falls back gracefully if there is no status line. Returns (headers, body,
    status_code). Multiple Set-Cookie headers are newline-folded.
    """
    text = text.replace("\r\n", "\n")
    status: Optional[int] = None

    first_nl = text.find("\n")
    first_line = text[:first_nl] if first_nl != -1 else text
    rest = text
    if re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", first_line):
        m = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", first_line)
        if m:
            status = int(m.group(1))
        rest = text[first_nl + 1:] if first_nl != -1 else ""

    if "\n\n" in rest:
        header_block, body = rest.split("\n\n", 1)
    else:
        header_block, body = rest, ""

    parsed = Parser().parsestr(header_block)
    headers: Dict[str, str] = {}
    for key in parsed.keys():
        values = parsed.get_all(key) or []
        lk = key.lower()
        if lk in headers:
            headers[lk] = headers[lk] + "\n" + "\n".join(values)
        else:
            headers[lk] = "\n".join(values)
    return headers, body, status


def fingerprint_response(text: str, target: Optional[str] = None) -> ReconResult:
    """Convenience: parse a raw HTTP response string and fingerprint it."""
    headers, body, status = load_response(text)
    return fingerprint(headers=headers, body=body, status=status, target=target)


def result_to_json(result: ReconResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
