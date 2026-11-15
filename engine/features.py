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

FEATURE_VERSION = "features-2.1"

BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google", "gmail", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "docusign", "dhl", "fedex",
    "hbl", "meezan", "ubl", "jazzcash", "easypaisa", "binance", "coinbase", "chase", "wellsfargo",
    # added after the PhreshPhish error analysis (crypto wallets, SaaS, delivery, gaming)
    "metamask", "trezor", "ledger", "trustwallet", "kraken", "bybit", "okx", "uniswap", "opensea",
    "canva", "adobe", "sharepoint", "onedrive", "wetransfer", "roblox", "discord",
    "usps", "royalmail", "evri", "verizon", "xfinity", "spotify", "airbnb", "ebay",
    # (left out on purpose: ups, att, zoom, steam, booking, telegram — too common as ordinary words)
]
# Hosting, site-builder, tunnel and file-sharing platforms where anyone can publish a page in
# minutes; phishing kits are heavily hosted there (PhreshPhish error analysis, Nov 2026).
FREE_HOSTING = (
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com", "github.io",
    "gitlab.io", "glitch.me", "herokuapp.com", "onrender.com", "repl.co", "replit.app", "fly.dev",
    "blogspot.", "wordpress.com", "weebly.com", "wixsite.com", "wix.com", "webflow.io", "framer.app",
    "godaddysites.com", "square.site", "sites.google.com", "carrd.co", "000webhostapp.com", "r2.dev",
    "backblazeb2.com", "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "ipfs.",
    "ngrok", "trycloudflare.com", "loca.lt", "azurewebsites.net", "firebasestorage.googleapis.com",
    "dweb.link", "fleek.co", "surge.sh", "translate.goog", "notion.site", "typedream.app", "mystrikingly.com",
)
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
              "surl.", "t.ly", "tiny.cc", "rebrand.ly", "s.id", "qrco.de", "ct.sendgrid.net", "click.",
              "l.ead.me", "linktr.ee")
TRACKER_IFRAME = re.compile(r"googletagmanager|doubleclick|facebook\.com/tr|bat\.bing|hotjar|youtube|vimeo|"
                            r"recaptcha|stripe|paypal\.com/sdk|hubspot|adsrvr|criteo|taboola|outbrain", re.I)
LOGIN_TERMS = ["sign in", "log in", "login", "signin", "verify", "password", "account", "wallet", "seed phrase",
               "recovery phrase", "connect wallet", "secret phrase", "private key"]
URGENCY_TERMS = [
    "urgent", "immediately", "suspended", "suspend", "locked", "unusual activity", "verify your account",
    "within 24 hours", "confirm your identity", "account will be closed", "action required", "unauthorized",
]
CREDENTIAL_TERMS = ["password", "passcode", "pin", "cvv", "card number", "otp", "social security", "cnic"]
SUSPICIOUS_URL_TOKENS = ["login", "signin", "verify", "secure", "account", "update", "banking", "confirm", "wallet", "webscr"]
# Most-abused TLDs (Spamhaus / Interisle phishing landscape reports) plus the ones in our error analysis.
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "country", "kim", "work",
                   "shop", "cyou", "icu", "buzz", "sbs", "cfd", "rest", "bond", "lol", "live", "online", "site",
                   "store", "cc", "support", "help", "monster", "quest", "best", "beauty", "hair", "skin"}
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
    # added in features-2.0 (real-data error analysis)
    "free_hosting", "url_shortener", "brand_in_host", "brand_typo_host", "host_entropy", "digits_in_host",
    "query_length", "num_inputs", "hidden_inputs", "email_inputs", "login_terms", "html_length_log",
    "title_length", "external_resource_ratio", "tracker_iframes", "brand_asset_hotlink", "wallet_seed_request",
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
    f["free_hosting"] = int(any(h in host for h in FREE_HOSTING))
    if f["free_hosting"]:
        ev["free_hosting"] = [host]
    f["url_shortener"] = int(any(host == x or host.endswith("." + x) or (x.endswith(".") and x in host)
                                 for x in SHORTENERS))
    if f["url_shortener"]:
        ev["url_shortener"] = [host]
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    on_host = [b for b in BRANDS if len(b) >= 4 and any(b in t for t in tokens) and not _domain_owns_brand(domain, b)]
    f["brand_in_host"] = int(bool(on_host))
    if on_host:
        ev["brand_in_host"] = [f"brand '{on_host[0]}' in host '{host}' (not the brand's domain)"]
    typo = _brand_typo(tokens, domain)
    f["brand_typo_host"] = int(bool(typo))
    if typo:
        ev["brand_typo_host"] = [f"'{typo[0]}' looks like '{typo[1]}'"]
    f["host_entropy"] = round(_entropy(host.replace(".", "")), 3) if host else 0.0
    f["digits_in_host"] = sum(c.isdigit() for c in host)
    f["query_length"] = len(parts.query)
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

    inputs = soup.find_all("input")
    itype = [(i.get("type") or "text").lower() for i in inputs]
    values["num_inputs"] = len(inputs)
    values["hidden_inputs"] = itype.count("hidden")
    values["email_inputs"] = itype.count("email") + sum(
        1 for i in inputs if re.search(r"e-?mail|user", (i.get("name") or "") + (i.get("id") or ""), re.I))

    # --- iframes -----------------------------------------------------------
    iframes = soup.find_all("iframe")
    values["num_iframes"] = len(iframes)
    trackers = [i for i in iframes if TRACKER_IFRAME.search(i.get("src") or "")]
    values["tracker_iframes"] = len(trackers)
    # Invisible analytics/consent iframes (Google Tag Manager etc.) are normal on real sites:
    # in rules-1.1 they made R06 fire on 64% of benign pages, so they no longer count as hidden.
    hidden = [i for i in iframes if _looks_hidden(i) and i not in trackers]
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

    resources = [t.get("src") or t.get("href") for t in soup.find_all(["img", "script", "link"])
                 if (t.get("src") or t.get("href"))]
    ext_res = [r for r in resources if _is_external(r, page_domain, url)]
    values["external_resource_ratio"] = round(len(ext_res) / len(resources), 3) if resources else 0.0
    # --- text --------------------------------------------------------------
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = soup.get_text(" ", strip=True)
    lower = (title + " " + text).lower()
    brands = [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", lower)]
    values["brand_mentions"] = len(brands)
    prominent = " ".join([title] + [t.get_text(" ", strip=True) for t in soup.find_all(["h1", "h2"])][:6]
                         + [i.get("alt", "") for i in soup.find_all("img")][:20]).lower()
    prominent_brands = [b for b in brands if re.search(rf"\b{re.escape(b)}\b", prominent)]
    mismatch = [b for b in prominent_brands if page_domain and not _domain_owns_brand(page_domain, b)]
    # A brand is the *headline* of the page (title, heading or logo) but the domain belongs to someone else.
    # (features-1.x used any mention in body text, which flagged news and "pay with PayPal" pages.)
    values["brand_domain_mismatch"] = int(bool(mismatch) and len(mismatch) == len(prominent_brands))

    # Brand *images/icons* pulled from the real brand's servers while the page claims to be that brand.
    # (features-2.0 counted any resource incl. SDK scripts, which fired on 59% of benign pages.)
    image_srcs = [t.get("src") for t in soup.find_all("img") if t.get("src")]
    image_srcs += [t.get("href") for t in soup.find_all("link", rel=True)
                   if "icon" in " ".join(t.get("rel")).lower() and t.get("href")]
    hotlinks = []
    for r in image_srcs:
        if not _is_external(r, page_domain, url):
            continue
        rdom = registrable_domain(_host_of(r, url)) or ""
        claimed = [b for b in prominent_brands if _domain_owns_brand(rdom, b)]
        if claimed and not (page_domain and _domain_owns_brand(page_domain, claimed[0])):
            hotlinks.append(f"{claimed[0]}: {_snippet(r, 80)}")
    values["brand_asset_hotlink"] = int(bool(hotlinks))
    if hotlinks:
        evidence["brand_asset_hotlink"] = hotlinks[:3]
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
    values["minimal_login_page"] = int(values["num_password_inputs"] > 0 and len(text) < 600 and len(links) < 3)
    lt = [t for t in LOGIN_TERMS if t in lower]
    values["login_terms"] = len(lt)
    if lt:
        evidence["login_terms"] = lt[:5]
    seed = re.search(r"seed phrase|recovery phrase|secret phrase|12[- ]word|24[- ]word|private key|mnemonic", lower)
    values["wallet_seed_request"] = int(bool(seed))
    if seed:
        evidence["wallet_seed_request"] = [seed.group(0)]
    values["html_length_log"] = round(math.log1p(len(html)), 3)
    values["title_length"] = len(title)

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


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_typo(tokens: list[str], domain: str) -> tuple[str, str] | None:
    """Host token within edit distance 1–2 of a brand (trzor~trezor, liive~live, paypai~paypal)."""
    for t in tokens:
        if len(t) < 5:
            continue
        for b in BRANDS:
            if len(b) < 5 or abs(len(t) - len(b)) > 2 or b in t:
                continue
            d = _levenshtein(t, b)
            if 1 <= d <= (1 if len(b) < 7 else 2) and not _domain_owns_brand(domain, b):
                return t, b
    return None


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
