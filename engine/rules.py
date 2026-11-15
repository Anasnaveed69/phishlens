"""Baseline rules (FR-3).

Each rule has a stable id, a human-readable name, a weight in (0, 1], a severity and a
reason template. Rules are combined with a noisy-OR:  score = 1 - Π(1 - weight_i)
over fired rules, so one strong indicator counts a lot and several weak ones add up,
but the score never exceeds 1. Admins can disable individual rules (stored in config).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .features import FeatureResult

RULESET_VERSION = "rules-1.1"


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
         and (_v("num_password_inputs")(f) > 0 or _v("credential_terms")(f) > 0),
         "The page names a well-known brand and asks for credentials, but is not hosted on that brand's domain.",
         "brand_domain_mismatch"),
    Rule("R05", "Credential request with urgency language", 0.40, "medium",
         lambda f: _v("credential_terms")(f) > 0 and _v("urgency_terms")(f) > 0,
         "The page pressures the user ('urgent', 'suspended', ...) while asking for credentials.", "urgency_terms"),
    Rule("R06", "Hidden iframe", 0.30, "medium", lambda f: _v("hidden_iframes")(f) > 0,
         "The page contains an invisible iframe.", "hidden_iframes"),
    Rule("R07", "Obfuscated JavaScript", 0.30, "medium", lambda f: _v("obfuscation_hits")(f) >= 2,
         "Inline script uses several obfuscation functions (eval/atob/unescape/...).", "obfuscation_hits"),
    Rule("R08", "Suspicious top-level domain", 0.20, "low", lambda f: _v("suspicious_tld")(f) == 1,
         "The domain uses a TLD that is frequently abused for phishing.", "suspicious_tld"),
    Rule("R09", "Excessive subdomains", 0.20, "low", lambda f: _v("num_subdomains")(f) >= 3,
         "The host has many subdomain levels, often used to look like a trusted site."),
    Rule("R10", "Punycode host", 0.35, "medium", lambda f: _v("has_punycode")(f) == 1,
         "The host uses punycode (xn--), which can disguise look-alike characters."),
    Rule("R11", "Login page without HTTPS", 0.25, "medium",
         lambda f: _v("num_password_inputs")(f) > 0 and _v("uses_https")(f) == 0 and _v("url_length")(f) > 0,
         "A password field is served over plain HTTP."),
    Rule("R12", "Brand logo or favicon loaded from elsewhere", 0.25, "low",
         lambda f: _v("external_logo")(f) == 1 or _v("external_favicon")(f) == 1,
         "The logo/favicon is pulled from a different domain (typical of cloned pages).", "external_logo"),
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
    Rule("R17", "Embedded data: / blob: document", 0.30, "medium", lambda f: _v("data_uri_count")(f) > 0,
         "The page embeds a whole document via a data:/blob: URI, a common way to hide phishing content.",
         "data_uri_count"),
    Rule("R18", "Look-alike brand domain", 0.50, "high", lambda f: _v("lookalike_brand_host")(f) == 1,
         "The host imitates a brand with swapped characters (e.g. 0 for o, rn for m).", "lookalike_brand_host"),
    Rule("R19", "Brand name in an unrelated domain's subdomain", 0.45, "high",
         lambda f: _v("brand_in_subdomain")(f) == 1,
         "A brand appears as a subdomain of someone else's domain (e.g. paypal.com.account-check.info).",
         "brand_in_subdomain"),
    Rule("R20", "Bare login page", 0.20, "low", lambda f: _v("minimal_login_page")(f) == 1,
         "The page is almost nothing but a password form, with very little other content."),
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
