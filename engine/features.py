"""Safe feature extraction from a saved page + its declared URL.

Safety rules (FR-2):
  * HTML is parsed with BeautifulSoup's pure-Python parser. Scripts are never executed,
    nothing is rendered, and no URL in the page is ever requested.
  * Evidence snippets are short and truncated so reports never carry the full page.

Feature groups: URL, DOM, text, and "visual-risk" signals that can be derived from
markup alone (external favicon/logo, brand-in-title mismatch, hidden elements).
"""
from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

FEATURE_VERSION = "features-1.1"

BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google", "gmail", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "docusign", "dhl", "fedex",
    "hbl", "meezan", "ubl", "jazzcash", "easypaisa", "binance", "coinbase", "chase", "wellsfargo",
]
URGENCY_TERMS = [
    "urgent", "immediately", "suspended", "suspend", "locked", "unusual activity", "verify your account",
    "within 24 hours", "confirm your identity", "account will be closed", "action required", "unauthorized",
]
CREDENTIAL_TERMS = ["password", "passcode", "pin", "cvv", "card number", "otp", "social security", "cnic"]
SUSPICIOUS_URL_TOKENS = ["login", "signin", "verify", "secure", "account", "update", "banking", "confirm", "wallet", "webscr"]
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "click", "country", "kim", "work"}
OBFUSCATION_PATTERNS = [r"\beval\s*\(", r"\batob\s*\(", r"\bunescape\s*\(", r"fromCharCode", r"document\.write\s*\("]
_MULTI_PART_SLD = {"co", "com", "org", "net", "gov", "edu", "ac"}

# Numeric features used by the ML model, in a fixed order. Changing this list
# requires retraining the model (the model stores the order it was trained with).
NUMERIC_FEATURES = [
    "url_length", "num_dots", "num_subdomains", "has_ip_host", "has_at_symbol", "hyphens_in_host",
    "uses_https", "suspicious_url_tokens", "has_punycode", "suspicious_tld", "path_depth", "has_port",
    "num_forms", "num_password_inputs", "external_form_action", "empty_or_js_form_action", "num_iframes",
    "hidden_iframes", "num_links", "external_link_ratio", "null_link_ratio", "num_scripts",
    "external_script_ratio", "has_meta_refresh", "obfuscation_hits", "disables_right_click",
    "brand_mentions", "brand_domain_mismatch", "urgency_terms", "credential_terms", "text_length_log",
    "external_favicon", "external_logo", "title_brand_mismatch", "hidden_elements",
    # added in features-1.1
    "form_action_ip", "data_uri_count", "lookalike_brand_host", "brand_in_subdomain", "minimal_login_page",
]
_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


@dataclass
class FeatureResult:
    values: dict[str, float]
    evidence: dict[str, list[str]] = field(default_factory=dict)
    page_domain: str | None = None
    brands_found: list[str] = field(default_factory=list)

    def vector(self) -> list[float]:
        return [float(self.values[name]) for name in NUMERIC_FEATURES]


def _snippet(text: str, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def registrable_domain(host: str | None) -> str | None:
    """Approximate eTLD+1 without network access (e.g. login.paypal.com -> paypal.com)."""
    if not host:
        return None
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in _MULTI_PART_SLD and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _host_of(url: str | None, base: str | None) -> str | None:
    if not url:
        return None
    try:
        absolute = urljoin(base or "", url.strip())
        return urlsplit(absolute).hostname
    except ValueError:
        return None


def _is_external(url: str | None, page_domain: str | None, base: str | None) -> bool:
    host = _host_of(url, base)
    if not host:
        return False  # relative link -> same site
    return page_domain is None or registrable_domain(host) != page_domain


def url_features(url: str | None) -> tuple[dict[str, float], dict[str, list[str]]]:
    f: dict[str, float] = {}
    ev: dict[str, list[str]] = {}
    parts = urlsplit(url or "")
    host = (parts.hostname or "").lower()
    f["url_length"] = len(url or "")
    f["num_dots"] = host.count(".")
    f["num_subdomains"] = max(0, host.count(".") - 1) if host else 0
    try:
        ipaddress.ip_address(host)
        f["has_ip_host"] = 1
        ev["has_ip_host"] = [host]
    except ValueError:
        f["has_ip_host"] = 0
    f["has_at_symbol"] = int("@" in (url or ""))
    f["hyphens_in_host"] = host.count("-")
    f["uses_https"] = int(parts.scheme == "https")
    tokens = [t for t in SUSPICIOUS_URL_TOKENS if t in (url or "").lower()]
    f["suspicious_url_tokens"] = len(tokens)
    if tokens:
        ev["suspicious_url_tokens"] = tokens
    f["has_punycode"] = int("xn--" in host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    f["suspicious_tld"] = int(tld in SUSPICIOUS_TLDS)
    if f["suspicious_tld"]:
        ev["suspicious_tld"] = ["." + tld]
    f["path_depth"] = len([p for p in parts.path.split("/") if p])
    domain = registrable_domain(host) or ""
    squashed = host.replace("-", "").replace(".", "")
    normalized = squashed.translate(_LOOKALIKE).replace("rn", "m").replace("vv", "w")
    looks = [b for b in BRANDS if len(b) >= 4 and b in normalized and b not in squashed
             and not _domain_owns_brand(domain, b)]
    f["lookalike_brand_host"] = int(bool(looks))
    if looks:
        ev["lookalike_brand_host"] = [f"'{host}' imitates '{looks[0]}'"]
    sub = host[: -len(domain)].rstrip(".") if domain and host.endswith(domain) else ""
    in_sub = [b for b in BRANDS if len(b) >= 4 and re.search(rf"(^|[.-]){re.escape(b)}([.-]|$)", sub)
              and not _domain_owns_brand(domain, b)]
    f["brand_in_subdomain"] = int(bool(in_sub))
    if in_sub:
        ev["brand_in_subdomain"] = [f"brand '{in_sub[0]}' in subdomain of '{domain}'"]
    try:
        f["has_port"] = int(parts.port is not None)
    except ValueError:
        f["has_port"] = 1
    return f, ev


def extract(html: str, url: str | None = None) -> FeatureResult:
    values, evidence = url_features(url)
    page_host = urlsplit(url).hostname if url else None
    page_domain = registrable_domain(page_host)

    soup = BeautifulSoup(html, "html.parser")

    # --- forms -------------------------------------------------------------
    forms = soup.find_all("form")
    values["num_forms"] = len(forms)
    values["num_password_inputs"] = len(soup.find_all("input", attrs={"type": re.compile("^password$", re.I)}))
    ext_actions, bad_actions = [], []
    for form in forms:
        action = (form.get("action") or "").strip()
        if not action or action == "#" or action.lower().startswith("javascript:"):
            bad_actions.append(action or "(empty)")
        elif action.lower().startswith("mailto:") or _is_external(action, page_domain, url):
            ext_actions.append(action)
    ip_actions = [a for a in ext_actions if _is_ip(_host_of(a, url))]
    values["form_action_ip"] = len(ip_actions)
    if ip_actions:
        evidence["form_action_ip"] = [_snippet(a) for a in ip_actions[:3]]
    values["external_form_action"] = len(ext_actions)
    values["empty_or_js_form_action"] = len(bad_actions)
    if ext_actions:
        evidence["external_form_action"] = [_snippet(a) for a in ext_actions[:3]]
    if bad_actions:
        evidence["empty_or_js_form_action"] = [_snippet(a) for a in bad_actions[:3]]

    data_uris = [v for t in soup.find_all(["iframe", "object", "embed", "form", "a", "script"])
                 for v in (t.get("src"), t.get("href"), t.get("action"), t.get("data"))
                 if isinstance(v, str) and v.strip().lower().startswith(("data:text/html", "data:application", "blob:"))]
    values["data_uri_count"] = len(data_uris)
    if data_uris:
        evidence["data_uri_count"] = [_snippet(d, 60) for d in data_uris[:3]]

    # --- iframes -----------------------------------------------------------
    iframes = soup.find_all("iframe")
    values["num_iframes"] = len(iframes)
    hidden = [i for i in iframes if _looks_hidden(i)]
    values["hidden_iframes"] = len(hidden)
    if hidden:
        evidence["hidden_iframes"] = [_snippet(i.get("src") or "(no src)") for i in hidden[:3]]

    # --- links -------------------------------------------------------------
    links = [a.get("href", "") for a in soup.find_all("a")]
    values["num_links"] = len(links)
    null_links = [h for h in links if not h.strip() or h.strip() == "#" or h.lower().startswith("javascript:")]
    ext_links = [h for h in links if h not in null_links and _is_external(h, page_domain, url)]
    values["external_link_ratio"] = round(len(ext_links) / len(links), 3) if links else 0.0
    values["null_link_ratio"] = round(len(null_links) / len(links), 3) if links else 0.0

    # --- scripts -----------------------------------------------------------
    scripts = soup.find_all("script")
    values["num_scripts"] = len(scripts)
    ext_scripts = [s.get("src") for s in scripts if s.get("src") and _is_external(s.get("src"), page_domain, url)]
    values["external_script_ratio"] = round(len(ext_scripts) / len(scripts), 3) if scripts else 0.0
    inline_js = " ".join(s.get_text() for s in scripts if not s.get("src"))
    inline_js += " " + " ".join(str(t.get("onload", "")) + str(t.get("onclick", "")) for t in soup.find_all(True))
    obf = [p for p in OBFUSCATION_PATTERNS if re.search(p, inline_js)]
    values["obfuscation_hits"] = len(obf)
    if obf:
        evidence["obfuscation_hits"] = [p.replace("\\b", "").replace("\\s*", "").replace("\\", "") for p in obf]
    values["disables_right_click"] = int(bool(re.search(r"contextmenu|event\.button\s*==\s*2", inline_js, re.I))
                                         or bool(soup.find(attrs={"oncontextmenu": True})))
    refresh = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
    values["has_meta_refresh"] = int(refresh is not None)
    if refresh is not None:
        evidence["has_meta_refresh"] = [_snippet(refresh.get("content", ""))]

    # --- text --------------------------------------------------------------
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = soup.get_text(" ", strip=True)
    lower = (title + " " + text).lower()
    brands = [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", lower)]
    values["brand_mentions"] = len(brands)
    mismatch = [b for b in brands if page_domain and not _domain_owns_brand(page_domain, b)]
    # Brand appears in the page but the page's own domain belongs to someone else.
    values["brand_domain_mismatch"] = int(bool(mismatch) and len(mismatch) == len(brands))
    if values["brand_domain_mismatch"]:
        evidence["brand_domain_mismatch"] = [f"brand '{b}' on domain '{page_domain}'" for b in mismatch[:3]]
    urg = [t for t in URGENCY_TERMS if t in lower]
    values["urgency_terms"] = len(urg)
    if urg:
        evidence["urgency_terms"] = urg[:5]
    cred = [t for t in CREDENTIAL_TERMS if re.search(rf"\b{re.escape(t)}\b", lower)]
    values["credential_terms"] = len(cred)
    if cred:
        evidence["credential_terms"] = cred[:5]
    values["text_length_log"] = round(math.log1p(len(text)), 3)
    values["minimal_login_page"] = int(values["num_password_inputs"] > 0 and len(text) < 600)

    # --- visual-risk (derived from markup only) ----------------------------
    icon = soup.find("link", rel=lambda r: r and "icon" in (" ".join(r) if isinstance(r, list) else r).lower())
    ext_icon = bool(icon and icon.get("href") and _is_external(icon.get("href"), page_domain, url))
    values["external_favicon"] = int(ext_icon)
    if ext_icon:
        evidence["external_favicon"] = [_snippet(icon.get("href"))]
    logos = [img for img in soup.find_all("img")
             if re.search(r"logo|brand", (img.get("src", "") + " " + img.get("alt", "") + " " + " ".join(img.get("class", []))), re.I)]
    ext_logos = [img.get("src") for img in logos if img.get("src") and _is_external(img.get("src"), page_domain, url)]
    values["external_logo"] = int(bool(ext_logos))
    if ext_logos:
        evidence["external_logo"] = [_snippet(s) for s in ext_logos[:3]]
    title_brands = [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", title.lower())]
    values["title_brand_mismatch"] = int(bool(title_brands) and bool(page_domain)
                                         and not any(_domain_owns_brand(page_domain, b) for b in title_brands))
    if values["title_brand_mismatch"]:
        evidence["title_brand_mismatch"] = [f"title: {_snippet(title, 80)}"]
    values["hidden_elements"] = sum(1 for t in soup.find_all(style=True)
                                    if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", t["style"], re.I))

    missing = [n for n in NUMERIC_FEATURES if n not in values]
    assert not missing, f"feature(s) not computed: {missing}"
    return FeatureResult(values=values, evidence=evidence, page_domain=page_domain, brands_found=brands)


def _is_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_owns_brand(domain: str, brand: str) -> bool:
    """True if the registrable domain plausibly belongs to the brand (paypal.com, meezanbank.com).
    Look-alikes such as paypal-secure-verify.tk or paypal.com.account-check.info return False."""
    label = domain.split(".")[0]
    return label == brand or (label.startswith(brand) and "-" not in label and len(label) <= len(brand) + 6)


def _looks_hidden(tag) -> bool:
    style = (tag.get("style") or "").replace(" ", "").lower()
    w, h = str(tag.get("width", "")).strip(), str(tag.get("height", "")).strip()
    return ("display:none" in style or "visibility:hidden" in style or w in {"0", "1", "0px", "1px"}
            or h in {"0", "1", "0px", "1px"} or tag.has_attr("hidden"))
