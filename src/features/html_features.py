"""
src/features/html_features.py
==============================
Fetches a web page via HTTP and extracts the 26 HTML/DOM-based features
used by the Case-4 model.

Features produced (26)
-----------------------
LineOfCode, LargestLineLength, HasTitle, HasFavicon, Robots,
IsResponsive, NoOfURLRedirect, NoOfSelfRedirect, HasDescription,
NoOfPopup, NoOfiFrame, HasExternalFormSubmit, HasSocialNet,
HasSubmitButton, HasHiddenFields, HasPasswordField, Bank, Pay, Crypto,
HasCopyrightInfo, NoOfImage, NoOfCSS, NoOfJS, NoOfSelfRef,
NoOfEmptyRef, NoOfExternalRef

NOT produced (excluded from Case-4)
-------------------------------------
DomainTitleMatchScore, URLTitleMatchScore
(Note: the page title IS extracted internally to compute HasTitle, but
 the two similarity scores above are never added to the output dict.)
"""

from __future__ import annotations

import logging
import re
import urllib.parse as _urlparse
from typing import Any

import requests
from bs4 import BeautifulSoup

from src.config import FETCH_RETRIES, FETCH_TIMEOUT, FETCH_USER_AGENT

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────
_SOCIAL_NETWORKS = {
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "youtube.com", "pinterest.com", "tiktok.com",
    "reddit.com", "snapchat.com", "tumblr.com", "whatsapp.com",
}

_BANK_KEYWORDS = {
    "bank", "banking", "banque", "banka", "banco",
    "credit", "savings", "account", "finance",
}
_PAY_KEYWORDS = {
    "pay", "payment", "paypal", "paiement", "checkout",
    "transaction", "transfer", "invoice", "wallet",
}
_CRYPTO_KEYWORDS = {
    "crypto", "bitcoin", "btc", "ethereum", "eth",
    "blockchain", "nft", "token", "defi", "binance",
    "coinbase", "wallet", "metamask",
}
_COPYRIGHT_PATTERNS = re.compile(
    r"(©|\&copy;|copyright|\(c\))", re.IGNORECASE
)


# ── HTTP fetch ────────────────────────────────────────────────────────────

def fetch_page(url: str) -> tuple[str, str, int]:
    """
    Fetch the HTML content of a URL.

    Returns
    -------
    (html_content, final_url, redirect_count)
      html_content   : raw HTML string (empty string on failure)
      final_url      : URL after following redirects
      redirect_count : number of HTTP redirects followed
    """
    headers = {"User-Agent": FETCH_USER_AGENT}
    session = requests.Session()

    for attempt in range(1, FETCH_RETRIES + 2):
        try:
            response = session.get(
                url,
                headers=headers,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True,
                verify=False,          # many phishing/test sites have bad certs
            )
            # Count redirects (history excludes the final response)
            redirect_count = len(response.history)
            final_url = response.url
            html = response.text
            logger.debug(
                "Fetched %s → %s (%d redirects, %d bytes)",
                url, final_url, redirect_count, len(html),
            )
            return html, final_url, redirect_count

        except requests.exceptions.SSLError:
            logger.warning("SSL error on attempt %d for %s", attempt, url)
            # Retry without verify is already set; likely a connectivity issue
            break
        except requests.exceptions.Timeout:
            logger.warning("Timeout on attempt %d for %s", attempt, url)
        except requests.exceptions.ConnectionError as exc:
            logger.warning("ConnectionError on attempt %d for %s: %s", attempt, url, exc)
            break
        except Exception as exc:
            logger.warning("Unexpected fetch error on attempt %d: %s", attempt, exc)
            break

    return "", url, 0


# ── Internal helpers ──────────────────────────────────────────────────────

def _get_domain(url: str) -> str:
    """Extract the netloc (hostname) from a URL, lower-cased."""
    try:
        parsed = _urlparse.urlparse(url if "://" in url else "http://" + url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _is_self_ref(href: str, page_domain: str) -> bool:
    """Return True if href points to the same domain (or is relative)."""
    if not href or href.startswith("#"):
        return True
    if href.startswith("/") or href.startswith("./") or href.startswith("../"):
        return True
    try:
        parsed = _urlparse.urlparse(href)
        if parsed.scheme in ("", "javascript", "mailto", "tel"):
            return True
        ref_domain = (parsed.hostname or "").lower()
        return ref_domain == page_domain or ref_domain == ""
    except Exception:
        return False


def _contains_keywords(text: str, keywords: set[str]) -> bool:
    """Return True if any keyword appears in the text (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _is_responsive(soup: BeautifulSoup) -> bool:
    """Heuristic: check for viewport meta tag or responsive CSS classes."""
    viewport = soup.find("meta", attrs={"name": re.compile("viewport", re.I)})
    if viewport:
        return True
    # Check for Bootstrap / Tailwind / media queries hint
    html_str = str(soup)[:5000]
    return "media" in html_str and ("max-width" in html_str or "min-width" in html_str)


# ── Main extraction function ──────────────────────────────────────────────

def extract_html_features(
    page_url: str,
    html: str,
    redirect_count: int = 0,
    self_redirect_count: int = 0,
) -> dict[str, Any]:
    """
    Parse HTML and extract the 26 DOM-based features.

    Parameters
    ----------
    page_url        : final URL of the page (after redirects)
    html            : raw HTML string
    redirect_count  : total HTTP redirects (NoOfURLRedirect)
    self_redirect_count : redirects to the same domain (NoOfSelfRedirect)

    Returns
    -------
    dict[str, Any] — 26 feature key-value pairs.
    DomainTitleMatchScore and URLTitleMatchScore are NEVER included.
    """
    if not html.strip():
        logger.warning("Empty HTML for %s — returning defaults.", page_url)
        return _default_html_features(redirect_count)

    soup = BeautifulSoup(html, "html.parser")
    page_domain = _get_domain(page_url)
    full_text = soup.get_text(" ", strip=True)

    # ── Line metrics ──────────────────────────────────────────────────────
    lines = html.splitlines()
    line_of_code = len(lines)
    largest_line_length = max((len(ln) for ln in lines), default=0)

    # ── Title ─────────────────────────────────────────────────────────────
    title_tag = soup.find("title")
    has_title = int(title_tag is not None and bool(title_tag.text.strip()))
    # Note: title text extracted for internal use only — NOT exposed as a feature

    # ── Favicon ───────────────────────────────────────────────────────────
    favicon = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower())
    has_favicon = int(favicon is not None)

    # ── Robots ────────────────────────────────────────────────────────────
    robots_meta = soup.find("meta", attrs={"name": re.compile("robots", re.I)})
    robots = int(robots_meta is not None)

    # ── Responsive ────────────────────────────────────────────────────────
    is_responsive = int(_is_responsive(soup))

    # ── Redirects (passed in from fetch_page) ────────────────────────────
    no_of_url_redirect = redirect_count
    no_of_self_redirect = self_redirect_count

    # ── Meta description ─────────────────────────────────────────────────
    desc_meta = soup.find("meta", attrs={"name": re.compile("description", re.I)})
    has_description = int(desc_meta is not None and desc_meta.get("content", "").strip() != "")

    # ── Popups (window.open in scripts) ─────────────────────────────────
    scripts = soup.find_all("script")
    script_text = " ".join(s.string or "" for s in scripts)
    no_of_popup = script_text.lower().count("window.open")

    # ── iFrames ───────────────────────────────────────────────────────────
    no_of_iframe = len(soup.find_all("iframe"))

    # ── External form submit ──────────────────────────────────────────────
    has_external_form_submit = 0
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action and not _is_self_ref(action, page_domain):
            has_external_form_submit = 1
            break

    # ── Social networks ───────────────────────────────────────────────────
    has_social_net = 0
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].lower()
        if any(sn in href for sn in _SOCIAL_NETWORKS):
            has_social_net = 1
            break

    # ── Submit button ─────────────────────────────────────────────────────
    submit_btn = soup.find("input", attrs={"type": re.compile("submit", re.I)})
    submit_btn2 = soup.find("button", attrs={"type": re.compile("submit", re.I)})
    has_submit_button = int(submit_btn is not None or submit_btn2 is not None)

    # ── Hidden fields ────────────────────────────────────────────────────
    hidden_fields = soup.find_all("input", attrs={"type": re.compile("hidden", re.I)})
    has_hidden_fields = int(len(hidden_fields) > 0)

    # ── Password field ───────────────────────────────────────────────────
    pwd_field = soup.find("input", attrs={"type": re.compile("password", re.I)})
    has_password_field = int(pwd_field is not None)

    # ── Keyword flags ────────────────────────────────────────────────────
    bank = int(_contains_keywords(full_text, _BANK_KEYWORDS))
    pay = int(_contains_keywords(full_text, _PAY_KEYWORDS))
    crypto = int(_contains_keywords(full_text, _CRYPTO_KEYWORDS))

    # ── Copyright ─────────────────────────────────────────────────────────
    has_copyright_info = int(bool(_COPYRIGHT_PATTERNS.search(full_text)))

    # ── Resource counts ───────────────────────────────────────────────────
    no_of_image = len(soup.find_all("img"))
    no_of_css = len(soup.find_all("link", rel=lambda r: r and "stylesheet" in " ".join(r).lower()))
    no_of_js = len(soup.find_all("script", src=True))

    # ── Link categorisation ───────────────────────────────────────────────
    all_hrefs = [a.get("href", "") for a in soup.find_all("a")]
    no_of_self_ref = 0
    no_of_empty_ref = 0
    no_of_external_ref = 0

    for href in all_hrefs:
        href = href.strip()
        if not href or href == "#" or href.lower().startswith("javascript"):
            no_of_empty_ref += 1
        elif _is_self_ref(href, page_domain):
            no_of_self_ref += 1
        else:
            no_of_external_ref += 1

    return {
        "LineOfCode": line_of_code,
        "LargestLineLength": largest_line_length,
        "HasTitle": has_title,
        "HasFavicon": has_favicon,
        "Robots": robots,
        "IsResponsive": is_responsive,
        "NoOfURLRedirect": no_of_url_redirect,
        "NoOfSelfRedirect": no_of_self_redirect,
        "HasDescription": has_description,
        "NoOfPopup": no_of_popup,
        "NoOfiFrame": no_of_iframe,
        "HasExternalFormSubmit": has_external_form_submit,
        "HasSocialNet": has_social_net,
        "HasSubmitButton": has_submit_button,
        "HasHiddenFields": has_hidden_fields,
        "HasPasswordField": has_password_field,
        "Bank": bank,
        "Pay": pay,
        "Crypto": crypto,
        "HasCopyrightInfo": has_copyright_info,
        "NoOfImage": no_of_image,
        "NoOfCSS": no_of_css,
        "NoOfJS": no_of_js,
        "NoOfSelfRef": no_of_self_ref,
        "NoOfEmptyRef": no_of_empty_ref,
        "NoOfExternalRef": no_of_external_ref,
    }


def _default_html_features(redirect_count: int = 0) -> dict[str, Any]:
    """Return zero-filled defaults when the page cannot be fetched."""
    return {
        "LineOfCode": 0,
        "LargestLineLength": 0,
        "HasTitle": 0,
        "HasFavicon": 0,
        "Robots": 0,
        "IsResponsive": 0,
        "NoOfURLRedirect": redirect_count,
        "NoOfSelfRedirect": 0,
        "HasDescription": 0,
        "NoOfPopup": 0,
        "NoOfiFrame": 0,
        "HasExternalFormSubmit": 0,
        "HasSocialNet": 0,
        "HasSubmitButton": 0,
        "HasHiddenFields": 0,
        "HasPasswordField": 0,
        "Bank": 0,
        "Pay": 0,
        "Crypto": 0,
        "HasCopyrightInfo": 0,
        "NoOfImage": 0,
        "NoOfCSS": 0,
        "NoOfJS": 0,
        "NoOfSelfRef": 0,
        "NoOfEmptyRef": 0,
        "NoOfExternalRef": 0,
    }
