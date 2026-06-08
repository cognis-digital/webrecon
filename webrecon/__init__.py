"""WEBRECON - defensive web technology fingerprinting from HTTP headers + body.

Identifies CMS, frameworks, servers, languages, CDNs and JS libraries from an
already-collected HTTP response (headers + body). Analysis/triage only: this
package performs NO network requests and has NO attack capability. It is meant
for authorized stack inventory, asset triage and detection engineering.
"""
from .core import (
    Finding,
    ReconResult,
    fingerprint,
    fingerprint_response,
    load_response,
)

TOOL_NAME = "webrecon"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "ReconResult",
    "fingerprint",
    "fingerprint_response",
    "load_response",
]
