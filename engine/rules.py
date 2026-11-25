"""Baseline rules (FR-3).

Each rule has a stable id, a human-readable name, a weight in (0, 1], a severity and a
reason template. Rules are combined with a noisy-OR:  score = 1 - Π(1 - weight_i)
over fired rules, so one strong indicator counts a lot and several weak ones add up,
but the score never exceeds 1. Admins can disable individual rules (stored in config).
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable

from .features import FeatureResult

RULESET_VERSION = "rules-2.1"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: float
    severity: str  # low | medium | high
    check: Callable[[FeatureResult], bool]
    reason: str
    evidence_key: str | None = None


def _v(name: str):
    return lambda fr: fr.values.get(name, 0)


RULES: list[Rule] = [
    Rule("R01", "IP address used as host", 0.45, "high", lambda f: _v("has_ip_host")(f) == 1,
         "The URL uses a raw IP address instead of a domain name.", "has_ip_host"),
    Rule("R02", "'@' symbol in URL", 0.35, "medium", lambda f: _v("has_at_symbol")(f) == 1,
         "An '@' in a URL makes browsers ignore everything before it, hiding the real host."),
    Rule("R03", "Password form posts to another domain", 0.60, "high",
         lambda f: _v("num_password_inputs")(f) > 0 and _v("external_form_action")(f) > 0,
         "A form asking for a password sends its data to a different domain.", "external_form_action"),
    # rules-1.1: R04 now needs a credential context (form, password field or credential words);
    # a plain article that merely mentions a brand was a false positive in rules-1.0.
    Rule("R04", "Brand impersonation", 0.50, "high",
         lambda f: _v("brand_domain_mismatch")(f) == 1
         and (_v("num_password_inputs")(f) > 0 or _v("credential_terms")(f) > 0 or _v("wallet_seed_request")(f) == 1),
         "The page's title/heading/logo claims a well-known brand and asks for credentials, "
         "but it is not hosted on that brand's domain.", "brand_domain_mismatch"),
    Rule("R05", "Credential request with urgency language", 0.40, "medium",
         lambda f: _v("credential_terms")(f) > 0 and _v("urgency_terms")(f) > 0,
         "The page pressures the user ('urgent', 'suspended', ...) while asking for credentials.", "urgency_terms"),
    # rules-2.1: R06/R07 alone fired on 56% / 1.7% of benign pages in PhreshPhish (precision 0.16 / 0.11),
    # so they now only count on pages that also ask for a password.
    Rule("R06", "Hidden iframe on a login page", 0.25, "medium",
         lambda f: _v("hidden_iframes")(f) > 0 and _v("num_password_inputs")(f) > 0,
         "A page asking for a password also contains an invisible iframe (not a known analytics frame).",
         "hidden_iframes"),
    Rule("R07", "Obfuscated JavaScript on a login page", 0.25, "medium",
         lambda f: _v("obfuscation_hits")(f) >= 2 and _v("num_password_inputs")(f) > 0,
         "A page asking for a password runs obfuscated inline script (eval/atob/unescape/...).", "obfuscation_hits"),
    Rule("R08", "Suspicious top-level domain", 0.20, "low", lambda f: _v("suspicious_tld")(f) == 1,
         "The domain uses a TLD that is frequently abused for phishing.", "suspicious_tld"),
    Rule("R09", "Excessive subdomains", 0.20, "low", lambda f: _v("num_subdomains")(f) >= 3,
         "The host has many subdomain levels, often used to look like a trusted site."),
    Rule("R10", "Punycode host", 0.35, "medium", lambda f: _v("has_punycode")(f) == 1,
         "The host uses punycode (xn--), which can disguise look-alike characters."),
    Rule("R11", "Login page without HTTPS", 0.25, "medium",
         lambda f: _v("num_password_inputs")(f) > 0 and _v("uses_https")(f) == 0 and _v("url_length")(f) > 0,
         "A password field is served over plain HTTP."),
    Rule("R12", "Brand logo hot-linked from the real brand", 0.35, "medium",
         lambda f: _v("brand_asset_hotlink")(f) == 1,
         "The page claims a brand and shows that brand's logo/icon straight from the brand's own servers, "
         "while not being hosted by the brand (typical of cloned pages).", "brand_asset_hotlink"),
    Rule("R13", "Brand in title but not in domain", 0.25, "low", lambda f: _v("title_brand_mismatch")(f) == 1,
         "The page title claims a brand that does not match the host.", "title_brand_mismatch"),
    Rule("R14", "Meta-refresh redirect", 0.15, "low", lambda f: _v("has_meta_refresh")(f) == 1,
         "The page automatically redirects the browser.", "has_meta_refresh"),
    Rule("R15", "Mostly dead links", 0.15, "low",
         lambda f: _v("num_links")(f) >= 3 and _v("null_link_ratio")(f) >= 0.6,
         "Most links go nowhere ('#' or javascript:), common in phishing kits."),
]

RULES += [
    Rule("R16", "Form submits to an IP address", 0.45, "high", lambda f: _v("form_action_ip")(f) > 0,
         "A form sends its data straight to a raw IP address.", "form_action_ip"),
    Rule("R17", "Embedded data: / blob: document", 0.30, "medium",
         lambda f: _v("data_uri_count")(f) > 0 and (_v("num_password_inputs")(f) > 0 or _v("num_forms")(f) > 0),
         "The page embeds a whole document via a data:/blob: URI, a common way to hide phishing content.",
         "data_uri_count"),
    Rule("R18", "Look-alike brand domain", 0.50, "high", lambda f: _v("lookalike_brand_host")(f) == 1,
         "The host imitates a brand with swapped characters (e.g. 0 for o, rn for m).", "lookalike_brand_host"),
    Rule("R19", "Brand name in an unrelated domain's subdomain", 0.45, "high",
         lambda f: _v("brand_in_subdomain")(f) == 1,
         "A brand appears as a subdomain of someone else's domain (e.g. paypal.com.account-check.info).",
         "brand_in_subdomain"),
    Rule("R20", "Bare login page", 0.20, "low", lambda f: _v("minimal_login_page")(f) == 1,
         "The page is almost nothing but a password form, with very little text and no navigation."),
    Rule("R21", "Free / anonymous hosting platform", 0.20, "low", lambda f: _v("free_hosting")(f) == 1,
         "The page is hosted on a platform where anyone can publish instantly (pages.dev, vercel.app, "
         "blogspot, storage buckets...).", "free_hosting"),
    Rule("R22", "Link shortener or redirect service", 0.30, "medium", lambda f: _v("url_shortener")(f) == 1,
         "The URL goes through a shortener/redirect service that hides the final destination.", "url_shortener"),
    Rule("R23", "Brand name in an unrelated host", 0.50, "high",
         lambda f: _v("brand_in_host")(f) == 1 and _v("brand_in_subdomain")(f) == 0,
         "A brand name is part of the host name, but the domain does not belong to that brand "
         "(e.g. metamasklogs.pages.dev).", "brand_in_host"),
    Rule("R24", "Misspelled brand in host", 0.50, "high", lambda f: _v("brand_typo_host")(f) == 1,
         "The host contains a near-miss spelling of a brand (e.g. trzor for trezor).", "brand_typo_host"),
    Rule("R25", "Wallet recovery phrase requested", 0.60, "high", lambda f: _v("wallet_seed_request")(f) == 1,
         "The page asks for a wallet seed/recovery phrase or private key; no legitimate site does this.",
         "wallet_seed_request"),
    Rule("R26", "Login page on free hosting", 0.40, "high",
         lambda f: _v("free_hosting")(f) == 1 and (_v("num_password_inputs")(f) > 0 or _v("login_terms")(f) >= 2),
         "A sign-in / wallet page is served from a free hosting platform instead of the service's own domain.",
         "login_terms"),
]

RULES_BY_ID = {r.id: r for r in RULES}


def evaluate(features: FeatureResult, disabled: list[str] | None = None) -> dict:
    disabled_set = set(disabled or [])
    fired = []
    remaining = 1.0
    for rule in RULES:
        if rule.id in disabled_set:
            continue
        if rule.check(features):
            remaining *= 1.0 - rule.weight
            fired.append({
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity,
                "weight": rule.weight,
                "reason": rule.reason,
                "evidence": features.evidence.get(rule.evidence_key, []) if rule.evidence_key else [],
            })
    return {
        "ruleset_version": RULESET_VERSION,
        "score": round(1.0 - remaining, 4),
        "fired": fired,
        "disabled": sorted(disabled_set),
    }
