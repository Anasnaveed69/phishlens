"""Property-based fuzzing (Hypothesis): the parser and validators must never crash, whatever bytes arrive.

Every input either raises a clean InputError (-> stable API error code) or yields a complete, finite
feature vector and a decision. Nothing is ever executed or fetched.
"""
from __future__ import annotations

import math

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from engine.features import NUMERIC_FEATURES, extract
from engine.pipeline import analyze
from engine.validation import InputError, read_dataset_zip, validate_label, validate_page, validate_url
import contextlib

CFG = {"phishing_threshold": 0.54, "suspicious_threshold": 0.42, "ml_weight": 0.8, "disabled_rules": []}
FAST = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])

tags = st.sampled_from(["html", "head", "body", "form", "input", "a", "iframe", "script", "img", "link", "meta",
                        "title", "div", "h1", "style", "object", "embed", "noscript", "svg", "table"])
attrs = st.sampled_from(["href", "src", "action", "type", "style", "rel", "alt", "width", "height", "hidden",
                         "http-equiv", "content", "onload", "oncontextmenu", "class", "name", "data"])
values = st.one_of(st.text(max_size=40), st.sampled_from([
    "javascript:alert(1)", "data:text/html;base64,PGgxPg==", "http://[::1", "//evil", "http://1.2.3.4:99999/x",
    "mailto:a@b", "#", "", "https://xn--pypal-4ve.com/", "display:none", "password", "icon", "0", "refresh",
    "http://paypal.com@evil.tk/", "%00", "‮", "../../etc/passwd"]))


@st.composite
def html_docs(draw):
    parts = []
    for _ in range(draw(st.integers(0, 25))):
        t = draw(tags)
        a = " ".join(f'{draw(attrs)}="{draw(values)}"' for _ in range(draw(st.integers(0, 3))))
        body = draw(st.text(max_size=30))
        closed = draw(st.booleans())
        parts.append(f"<{t} {a}>{body}" + (f"</{t}>" if closed else ""))
    return "".join(parts)


urls = st.one_of(st.none(), values, st.from_regex(r"https?://[a-z0-9.\-]{1,30}(:[0-9]{1,6})?(/[a-z0-9._~%-]{0,20}){0,3}",
                                                    fullmatch=True))


@FAST
@given(html=html_docs(), url=urls)
def test_feature_extraction_never_crashes(html, url):
    try:
        url = validate_url(url) if isinstance(url, str) else None
    except InputError:
        url = None
    fr = extract(html, url)
    vec = fr.vector()
    assert len(vec) == len(NUMERIC_FEATURES) and all(math.isfinite(v) for v in vec)
    r = analyze(html, url, CFG, None)
    assert r["decision"] in {"phishing", "suspicious", "benign"} and 0 <= r["score"] <= 1


@FAST
@given(data=st.binary(max_size=3000), name=st.text(max_size=40))
def test_page_validation_only_raises_input_error(data, name):
    try:
        page = validate_page(name, data, 2000)
    except InputError as exc:
        assert exc.code in {"UNSUPPORTED_TYPE", "INVALID_INPUT", "FILE_TOO_LARGE"}
    else:
        assert page.filename and "/" not in page.filename and len(data) <= 2000


@FAST
@given(url=st.text(max_size=300))
def test_url_validation_only_raises_input_error(url):
    try:
        out = validate_url(url)
    except InputError as exc:
        assert exc.code == "INVALID_INPUT"
    else:
        assert out is None or out.lower().startswith(("http://", "https://"))


@FAST
@given(label=st.one_of(st.none(), st.text(max_size=20)))
def test_label_validation(label):
    try:
        out = validate_label(label)
    except InputError:
        return
    assert out in {None, "phishing", "benign"}


@FAST
@given(data=st.binary(max_size=2000))
def test_zip_reader_never_crashes_on_garbage(data):
    with contextlib.suppress(InputError):
        read_dataset_zip(data, 10_000, 10, 5_000)
