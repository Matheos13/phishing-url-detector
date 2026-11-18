"""Tests for feature extraction, prediction and the Flask app.

No dataset or trained model is needed: a small fake model stands in for
model.joblib so the tests run anywhere, including CI.
"""
import importlib
import sys
from pathlib import Path

import joblib
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from features import extract_features, normalize  # noqa: E402

FEATURE_NAMES = [
    "url_length", "host_length", "num_dots", "num_hyphens", "num_digits",
    "num_subdomains", "has_at", "has_ip", "uses_https", "num_suspicious_words",
    "path_length", "num_params", "is_top_domain",
]


# --- normalize -------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("https://example.com/page", "example.com/page"),
    ("http://example.com", "example.com/"),
    ("  example.com  ", "example.com/"),
    ("example.com/a/b", "example.com/a/b"),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_uses_https_reads_the_original_scheme():
    assert extract_features("https://example.com/x")["uses_https"] == 1
    assert extract_features("HTTPS://example.com/x")["uses_https"] == 1
    assert extract_features("http://example.com/x")["uses_https"] == 0
    assert extract_features("example.com/x")["uses_https"] == 0


def test_scheme_only_changes_uses_https():
    with_scheme = extract_features("https://example.com/x")
    without = extract_features("example.com/x")
    with_scheme.pop("uses_https")
    without.pop("uses_https")
    assert with_scheme == without


# --- extract_features ------------------------------------------------------

def test_returns_every_feature_as_int():
    feats = extract_features("example.com/login")
    assert list(feats) == FEATURE_NAMES
    assert all(isinstance(v, int) for v in feats.values())


def test_counts_dots_hyphens_digits():
    feats = extract_features("my-site-123.example.com/")
    assert feats["num_dots"] == 2
    assert feats["num_hyphens"] == 2
    assert feats["num_digits"] == 3


def test_detects_ip_host():
    assert extract_features("http://192.168.0.1/login")["has_ip"] == 1
    assert extract_features("example.com/")["has_ip"] == 0


def test_detects_at_sign():
    assert extract_features("example.com@evil.xyz/")["has_at"] == 1


def test_counts_subdomains():
    assert extract_features("a.b.example.com/")["num_subdomains"] == 2
    assert extract_features("example.com/")["num_subdomains"] == 0


def test_counts_suspicious_words():
    feats = extract_features("paypal.secure-login.verify-account.xyz/update")
    # paypal, secure, login, verify, account, update
    assert feats["num_suspicious_words"] == 6
    assert extract_features("wikipedia.org/wiki/Cat")["num_suspicious_words"] == 0


def test_counts_query_params():
    assert extract_features("example.com/search?q=a&page=2")["num_params"] == 2
    assert extract_features("example.com/")["num_params"] == 0


def test_path_length():
    assert extract_features("example.com/abc")["path_length"] == len("/abc")


def test_malformed_url_does_not_crash():
    feats = extract_features("http://[broken.example.com/login")
    assert list(feats) == FEATURE_NAMES


# --- predict + Flask app (with a fake model) --------------------------------

class FakeModel:
    """Says 'phishing' whenever the URL contains a suspicious word."""

    def predict_proba(self, X):
        return [[0.1, 0.9] if n > 0 else [0.9, 0.1] for n in X["num_suspicious_words"]]


@pytest.fixture
def fresh_modules(monkeypatch):
    bundle = {"model": FakeModel(), "columns": FEATURE_NAMES}
    monkeypatch.setattr(joblib, "load", lambda path: bundle)
    for name in ("predict", "app"):
        sys.modules.pop(name, None)
    yield
    for name in ("predict", "app"):
        sys.modules.pop(name, None)


def test_check_url_verdicts(fresh_modules):
    predict = importlib.import_module("predict")

    bad = predict.check_url("paypal.secure-login.xyz/verify")
    assert bad["verdict"] == "Likely phishing"
    assert bad["phishing_probability"] == 0.9
    assert set(bad["features"]) == set(FEATURE_NAMES)

    good = predict.check_url("wikipedia.org/wiki/Cat")
    assert good["verdict"] == "Likely safe"
    assert good["phishing_probability"] == 0.1


def test_home_page_loads(fresh_modules):
    client = importlib.import_module("app").app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Phishing URL Detector" in resp.data


def test_form_post_shows_verdict(fresh_modules):
    client = importlib.import_module("app").app.test_client()
    resp = client.post("/", data={"url": "paypal.secure-login.xyz/verify"})
    assert resp.status_code == 200
    assert b"Likely phishing" in resp.data


def test_empty_post_shows_no_result(fresh_modules):
    client = importlib.import_module("app").app.test_client()
    resp = client.post("/", data={"url": "   "})
    assert resp.status_code == 200
    assert b"Phishing probability" not in resp.data
