import re
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "account", "bank", "confirm", "paypal", "signin"]
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def extract_features(url: str) -> dict:
    url = str(url)
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.netloc.split(":")[0]
        scheme, path = parsed.scheme, parsed.path
    except ValueError:
        # Malformed URL (e.g. stray "[") - fall back to simple string handling
        scheme = "https" if url.startswith("https") else "http"
        host = url.split("/")[0]
        path = url[len(host):]
    ext = tldextract.extract(url)

    return {
        "url_length": len(url),
        "host_length": len(host),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "has_at": int("@" in url),
        "has_ip": int(bool(IP_PATTERN.match(host))),
        "uses_https": int(scheme == "https"),
        "num_suspicious_words": sum(w in url.lower() for w in SUSPICIOUS_WORDS),
        "path_length": len(path),
        "num_params": url.count("&") + (1 if "?" in url else 0),
    }

    