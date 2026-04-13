"""
src/features/url_features.py
=============================
Extracts the 19 URL-based features used by the Case-4 model.

These features can be computed from the raw URL string alone — no HTTP
request is needed.  The logic mirrors the PhiUSIIL dataset construction.

Features produced (in definition order)
----------------------------------------
URLLength, DomainLength, IsDomainIP, TLD, TLDLength,
NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL,
NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsHTTPS

NOT produced (excluded from Case-4 model)
-----------------------------------------
URLSimilarityIndex, TLDLegitimateProb, URLCharProb, CharContinuationRate
"""

from __future__ import annotations

import ipaddress
import logging
import re
import urllib.parse as _urlparse
from typing import Any

logger = logging.getLogger(__name__)

# ── Character sets ────────────────────────────────────────────────────────
# "Special" characters beyond letters/digits AND the standard URL delimiters
# (=, ?, &, /, ., -, _, ~, :, @, #)
_STANDARD_URL_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-._~:/?#[]@!$&'()*+,;=%"
)
_OTHER_SPECIAL_CHARS_PATTERN = re.compile(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]")

# Obfuscation patterns (URL encoding sequences like %XX)
_OBFUSCATION_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

# Known common TLDs (same top-level set referenced implicitly by the dataset)
_LEGIT_TLDS: frozenset[str] = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co", "io", "info", "biz", "us", "uk", "de", "fr",
    "ca", "au", "jp", "cn", "br", "in", "ru", "nl", "it",
    "es", "pl", "se", "no", "fi", "dk", "be", "ch", "at",
    "nz", "za", "mx", "ar", "cl", "sg", "hk", "tw", "kr",
})


# ── Helpers ───────────────────────────────────────────────────────────────

def _parse_url(url: str) -> _urlparse.ParseResult:
    """Parse URL, adding scheme if missing."""
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url
    return _urlparse.urlparse(url)


def _extract_domain_and_subdomains(parsed: _urlparse.ParseResult) -> tuple[str, list[str]]:
    """
    Return (registrable_domain, list_of_subdomains).

    e.g. "mail.google.com" → ("google.com", ["mail"])
         "a.b.paypal.com"  → ("paypal.com", ["a", "b"])
    """
    hostname = parsed.hostname or ""
    parts = hostname.split(".")

    # Handle known two-part TLDs (co.uk, com.br, etc.)
    two_part_tlds = {
        "co.uk", "co.in", "co.nz", "co.za", "com.au", "com.br",
        "com.mx", "com.ar", "com.cn", "net.au", "org.uk", "ac.uk",
    }
    if len(parts) >= 3:
        candidate = ".".join(parts[-2:])
        if candidate in two_part_tlds:
            # registrable = last 3 parts
            domain = ".".join(parts[-3:]) if len(parts) >= 3 else hostname
            subdomains = parts[:-3]
        else:
            domain = ".".join(parts[-2:])
            subdomains = parts[:-2]
    elif len(parts) == 2:
        domain = hostname
        subdomains = []
    else:
        domain = hostname
        subdomains = []

    return domain, subdomains


def _is_ip(hostname: str) -> bool:
    """Return True if the hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _get_tld(parsed: _urlparse.ParseResult) -> str:
    """Return the top-level domain (last label of hostname), lower-cased."""
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    return parts[-1].lower() if parts else ""


# ── Main extraction function ──────────────────────────────────────────────

def extract_url_features(url: str) -> dict[str, Any]:
    """
    Extract the 19 URL-based features aligned with the Case-4 model.

    Parameters
    ----------
    url : str
        Raw URL string (with or without scheme).

    Returns
    -------
    dict[str, Any]
        Feature dictionary.  Keys match exactly the column names expected
        by the model.  None of the 6 excluded features is included.
    """
    try:
        parsed = _parse_url(url)
        full_url = url  # keep original for length / char counts
    except Exception as exc:
        logger.warning("URL parse error for '%s': %s — returning defaults.", url, exc)
        return _default_url_features()

    hostname = parsed.hostname or ""
    _, subdomains = _extract_domain_and_subdomains(parsed)
    tld = _get_tld(parsed)

    # ── 1. URLLength ──────────────────────────────────────────────────────
    url_length = len(full_url)

    # ── 2. DomainLength ──────────────────────────────────────────────────
    domain_length = len(hostname)

    # ── 3. IsDomainIP ────────────────────────────────────────────────────
    is_domain_ip = int(_is_ip(hostname))

    # ── 4. TLD (categorical) ─────────────────────────────────────────────
    tld_value = tld  # raw string, e.g. "com", "net", "xyz"

    # ── 5. TLDLength ─────────────────────────────────────────────────────
    tld_length = len(tld)

    # ── 6. NoOfSubDomain ─────────────────────────────────────────────────
    no_of_subdomain = len(subdomains)

    # ── 7 & 8 & 9. Obfuscation (%-encoding) ──────────────────────────────
    obfuscated_matches = _OBFUSCATION_PATTERN.findall(full_url)
    has_obfuscation = int(len(obfuscated_matches) > 0)
    no_of_obfuscated_char = len(obfuscated_matches)
    obfuscation_ratio = (
        no_of_obfuscated_char / url_length if url_length > 0 else 0.0
    )

    # ── 10 & 11. Letters ─────────────────────────────────────────────────
    letters = [c for c in full_url if c.isalpha()]
    no_of_letters = len(letters)
    letter_ratio = no_of_letters / url_length if url_length > 0 else 0.0

    # ── 12 & 13. Digits ──────────────────────────────────────────────────
    digits = [c for c in full_url if c.isdigit()]
    no_of_digits = len(digits)
    digit_ratio = no_of_digits / url_length if url_length > 0 else 0.0

    # ── 14. Equals signs ─────────────────────────────────────────────────
    no_of_equals = full_url.count("=")

    # ── 15. Question marks ───────────────────────────────────────────────
    no_of_qmarks = full_url.count("?")

    # ── 16. Ampersands ───────────────────────────────────────────────────
    no_of_ampersands = full_url.count("&")

    # ── 17 & 18. Other special chars ─────────────────────────────────────
    other_special = _OTHER_SPECIAL_CHARS_PATTERN.findall(full_url)
    no_of_other_special = len(other_special)
    special_char_ratio = no_of_other_special / url_length if url_length > 0 else 0.0

    # ── 19. IsHTTPS ───────────────────────────────────────────────────────
    is_https = int(parsed.scheme.lower() == "https")

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLD": tld_value,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated_char,
        "ObfuscationRatio": round(obfuscation_ratio, 6),
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": round(letter_ratio, 6),
        "NoOfDegitsInURL": no_of_digits,
        "DegitRatioInURL": round(digit_ratio, 6),
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmarks,
        "NoOfAmpersandInURL": no_of_ampersands,
        "NoOfOtherSpecialCharsInURL": no_of_other_special,
        "SpacialCharRatioInURL": round(special_char_ratio, 6),
        "IsHTTPS": is_https,
    }


def _default_url_features() -> dict[str, Any]:
    """Return zero-filled defaults when URL parsing fails."""
    return {
        "URLLength": 0,
        "DomainLength": 0,
        "IsDomainIP": 0,
        "TLD": "",
        "TLDLength": 0,
        "NoOfSubDomain": 0,
        "HasObfuscation": 0,
        "NoOfObfuscatedChar": 0,
        "ObfuscationRatio": 0.0,
        "NoOfLettersInURL": 0,
        "LetterRatioInURL": 0.0,
        "NoOfDegitsInURL": 0,
        "DegitRatioInURL": 0.0,
        "NoOfEqualsInURL": 0,
        "NoOfQMarkInURL": 0,
        "NoOfAmpersandInURL": 0,
        "NoOfOtherSpecialCharsInURL": 0,
        "SpacialCharRatioInURL": 0.0,
        "IsHTTPS": 0,
    }
