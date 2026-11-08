# =========================================================
# PHISHING URL DETECTOR
# Basic URL Structure Analysis
# =========================================================

import re
from urllib.parse import urlparse


# =========================================================
# SUSPICIOUS KEYWORDS
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "signin",
    "bank",
    "wallet",
    "payment",
    "billing",
    "credential",
    "unlock",
    "security"
]


# =========================================================
# URL SHORTENERS
# =========================================================

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy"
]


# =========================================================
# IP ADDRESS CHECK
# =========================================================

def is_ip_address(host):

    if not host:
        return False

    return bool(
        re.fullmatch(
            r"\d{1,3}(\.\d{1,3}){3}",
            host
        )
    )


# =========================================================
# MAIN URL ANALYSIS
# =========================================================

def analyze_url(url):

    # -----------------------------------------------------
    # Parse URL
    # -----------------------------------------------------

    try:

        parsed = urlparse(url)

    except Exception:

        return {
            "url": url,
            "result": "Invalid URL",
            "level": "high",
            "score": 100,
            "breakdown": {
                "protocol": "-",
                "domain": "-",
                "path": "-",
                "query": "-"
            },
            "features": {},
            "feature_status": {},
            "reasons": [
                "The URL could not be parsed."
            ]
        }


    protocol = (
        parsed.scheme.lower()
        if parsed.scheme
        else ""
    )

    domain = (
        parsed.hostname
        if parsed.hostname
        else ""
    )

    path = (
        parsed.path
        if parsed.path
        else "/"
    )

    query = (
        parsed.query
        if parsed.query
        else ""
    )


    # =====================================================
    # BASIC FEATURES
    # =====================================================

    url_length = len(url)

    domain_length = len(domain)

    path_length = len(path)


    # -----------------------------------------------------
    # IP ADDRESS
    # -----------------------------------------------------

    ip_address = is_ip_address(
        domain
    )


    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    https = protocol == "https"


    # -----------------------------------------------------
    # SUBDOMAINS
    # -----------------------------------------------------

    subdomains = 0

    if domain:

        parts = domain.split(".")

        if len(parts) > 2:

            subdomains = len(parts) - 2


    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    url_lower = url.lower()

    suspicious_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            suspicious_keywords.append(
                keyword
            )


    # -----------------------------------------------------
    # @ SYMBOL
    # -----------------------------------------------------

    at_symbol = "@" in url


    # -----------------------------------------------------
    # URL SHORTENER
    # -----------------------------------------------------

    shortened_url = False

    if domain:

        shortened_url = (
            domain.lower()
            in URL_SHORTENERS
        )


    # -----------------------------------------------------
    # PUNYCODE
    # -----------------------------------------------------

    punycode = (
        "xn--" in domain.lower()
        if domain
        else False
    )


    # -----------------------------------------------------
    # PORT
    # -----------------------------------------------------

    port = parsed.port

    non_standard_port = (
        port is not None
        and port not in [80, 443]
    )


    # -----------------------------------------------------
    # DIGITS
    # -----------------------------------------------------

    digits = sum(
        char.isdigit()
        for char in url
    )


    digit_ratio = round(
        (digits / url_length) * 100,
        2
    ) if url_length > 0 else 0


    # -----------------------------------------------------
    # DOTS
    # -----------------------------------------------------

    dots = url.count(".")


    # -----------------------------------------------------
    # HYPHENS
    # -----------------------------------------------------

    hyphens = url.count("-")


    # -----------------------------------------------------
    # SPECIAL CHARACTERS
    # -----------------------------------------------------

    special_characters = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )


    # -----------------------------------------------------
    # QUERY PARAMETERS
    # -----------------------------------------------------

    query_parameters = 0

    if query:

        query_parameters = len(
            query.split("&")
        )


    # =====================================================
    # FEATURES OBJECT
    # =====================================================

    features = {

        "https": https,

        "ip_address": ip_address,

        "suspicious_keywords":
            suspicious_keywords,

        "subdomains": subdomains,

        "at_symbol": at_symbol,

        "shortened_url":
            shortened_url,

        "punycode": punycode,

        "port": port,

        "url_length": url_length,

        "domain_length": domain_length,

        "path_length": path_length,

        "digits": digits,

        "digit_ratio": digit_ratio,

        "dots": dots,

        "hyphens": hyphens,

        "special_characters":
            special_characters,

        "query_parameters":
            query_parameters
    }


    # =====================================================
    # FEATURE STATUS
    # =====================================================

    feature_status = {

        "https": {
            "status":
                "safe"
                if https
                else "warning"
        },

        "ip_address": {
            "status":
                "warning"
                if ip_address
                else "safe"
        },

        "suspicious_keywords": {
            "status":
                "warning"
                if suspicious_keywords
                else "safe"
        },

        "subdomains": {
            "status":
                "warning"
                if subdomains >= 3
                else "safe"
        },

        "at_symbol": {
            "status":
                "warning"
                if at_symbol
                else "safe"
        },

        "shortened_url": {
            "status":
                "warning"
                if shortened_url
                else "safe"
        },

        "punycode": {
            "status":
                "warning"
                if punycode
                else "safe"
        },

        "non_standard_port": {
            "status":
                "warning"
                if non_standard_port
                else "safe"
        }
    }


    # =====================================================
    # RISK SCORE
    # =====================================================

    score = 0

    reasons = []


    # -----------------------------------------------------
    # HTTP
    # -----------------------------------------------------

    if not https:

        score += 10

        reasons.append(
            "The URL does not use HTTPS."
        )


    # -----------------------------------------------------
    # IP ADDRESS
    # -----------------------------------------------------

    if ip_address:

        score += 20

        reasons.append(
            "The URL uses an IP address instead of a domain name."
        )


    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    if suspicious_keywords:

        score += min(
            20,
            len(suspicious_keywords) * 5
        )

        reasons.append(
            "Suspicious keywords detected: "
            +
            ", ".join(
                suspicious_keywords
            )
        )


    # -----------------------------------------------------
    # SUBDOMAINS
    # -----------------------------------------------------

    if subdomains >= 3:

        score += 10

        reasons.append(
            "The URL contains an unusually high number of subdomains."
        )


    # -----------------------------------------------------
    # @ SYMBOL
    # -----------------------------------------------------

    if at_symbol:

        score += 20

        reasons.append(
            "The URL contains an @ symbol."
        )


    # -----------------------------------------------------
    # SHORTENER
    # -----------------------------------------------------

    if shortened_url:

        score += 15

        reasons.append(
            "A URL shortening service was detected."
        )


    # -----------------------------------------------------
    # PUNYCODE
    # -----------------------------------------------------

    if punycode:

        score += 15

        reasons.append(
            "The domain uses Punycode."
        )


    # -----------------------------------------------------
    # NON-STANDARD PORT
    # -----------------------------------------------------

    if non_standard_port:

        score += 10

        reasons.append(
            "A non-standard port was detected."
        )


    # -----------------------------------------------------
    # LONG URL
    # -----------------------------------------------------

    if url_length > 100:

        score += 10

        reasons.append(
            "The URL is unusually long."
        )


    # -----------------------------------------------------
    # MANY DIGITS
    # -----------------------------------------------------

    if digit_ratio > 20:

        score += 10

        reasons.append(
            "The URL contains a high proportion of digits."
        )


    # -----------------------------------------------------
    # MANY HYPHENS
    # -----------------------------------------------------

    if hyphens >= 4:

        score += 5

        reasons.append(
            "The URL contains many hyphens."
        )


    # -----------------------------------------------------
    # CAP SCORE
    # -----------------------------------------------------

    score = min(
        score,
        100
    )


    # =====================================================
    # RISK LEVEL
    # =====================================================

    if score >= 60:

        level = "high"

        result_text = "High Risk"

    elif score >= 30:

        level = "medium"

        result_text = "Suspicious"

    else:

        level = "low"

        result_text = "Low Risk"


    # =====================================================
    # IF NO REASONS
    # =====================================================

    if not reasons:

        reasons.append(
            "No major suspicious URL characteristics were detected."
        )


    # =====================================================
    # FINAL RESULT
    # =====================================================

    return {

        "url": url,

        "result": result_text,

        "level": level,

        "score": score,

        "breakdown": {

            "protocol":
                protocol or "-",

            "domain":
                domain or "-",

            "path":
                path,

            "query":
                query or "None"
        },

        "features": features,

        "feature_status":
            feature_status,

        "reasons": reasons
    }