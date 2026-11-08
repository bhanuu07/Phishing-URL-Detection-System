# =========================================================
# LOOKALIKE / TYPOSQUATTING DOMAIN DETECTOR
# =========================================================

import re
from urllib.parse import urlparse


# ---------------------------------------------------------
# KNOWN BRANDS
# ---------------------------------------------------------

KNOWN_BRANDS = {
    "google",
    "facebook",
    "instagram",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "youtube",
    "linkedin",
    "twitter",
    "github",
    "whatsapp",
    "telegram",
    "flipkart",
    "myntra",
    "sbi",
    "hdfc",
    "icici",
    "phonepe",
    "paytm"
}


# ---------------------------------------------------------
# CHARACTER CONFUSION MAP
# ---------------------------------------------------------

CONFUSABLE_CHARACTERS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "@": "a"
}


# ---------------------------------------------------------
# NORMALIZE DOMAIN
# ---------------------------------------------------------

def normalize_domain(domain):

    # Only remove www.
    # Do NOT lowercase here because we need to detect
    # mixed capitalization such as gOOgle.com.

    if domain.startswith("www.") or domain.startswith("WWW."):
        domain = domain[4:]

    return domain


# ---------------------------------------------------------
# REMOVE TLD
# ---------------------------------------------------------

def get_domain_name(domain):

    parts = domain.split(".")

    if len(parts) >= 2:
        return parts[-2]

    return parts[0]


# ---------------------------------------------------------
# NORMALIZE LOOKALIKE CHARACTERS
# ---------------------------------------------------------

def normalize_lookalike(text):

    result = ""

    for char in text.lower():

        if char in CONFUSABLE_CHARACTERS:
            result += CONFUSABLE_CHARACTERS[char]

        else:
            result += char

    return result


# ---------------------------------------------------------
# LEVENSHTEIN DISTANCE
# ---------------------------------------------------------

def levenshtein_distance(a, b):

    if a == b:
        return 0

    if len(a) < len(b):
        a, b = b, a

    previous_row = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):

        current_row = [i]

        for j, char_b in enumerate(b, start=1):

            insert_cost = current_row[j - 1] + 1

            delete_cost = previous_row[j] + 1

            replace_cost = (
                previous_row[j - 1]
                + (char_a != char_b)
            )

            current_row.append(
                min(
                    insert_cost,
                    delete_cost,
                    replace_cost
                )
            )

        previous_row = current_row

    return previous_row[-1]


# ---------------------------------------------------------
# CALCULATE SIMILARITY
# ---------------------------------------------------------

def similarity(a, b):

    if not a or not b:
        return 0

    distance = levenshtein_distance(a, b)

    longest = max(len(a), len(b))

    return round(
        (1 - distance / longest) * 100,
        2
    )


# ---------------------------------------------------------
# CHECK LOOKALIKE DOMAIN
# ---------------------------------------------------------

def detect_lookalike(url):

    result = {
        "detected": False,
        "mixed_case": False,
        "domain": None,
        "matched_brand": None,
        "similarity": 0,
        "reason": None
    }


    # -----------------------------------------------------
    # Parse URL
    # -----------------------------------------------------

    try:

        parsed = urlparse(url)

        # IMPORTANT:
        # parsed.hostname converts the hostname to lowercase.
        # parsed.netloc keeps the original capitalization.

        domain = parsed.netloc

        # Remove username/password if present
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]

    except Exception:

        return result


    if not domain:

        return result


    # -----------------------------------------------------
    # Detect mixed capitalization
    # -----------------------------------------------------

    letters = [
        char for char in domain
        if char.isalpha()
    ]

    has_uppercase = any(
        char.isupper()
        for char in letters
    )

    has_lowercase = any(
        char.islower()
        for char in letters
    )


    if has_uppercase and has_lowercase:

        result["mixed_case"] = True

        result["detected"] = True

        result["reason"] = (
            f"Domain '{domain}' uses mixed capitalization."
        )


    # -----------------------------------------------------
    # Normalize domain for lookalike comparison
    # -----------------------------------------------------

    domain = normalize_domain(domain)

    result["domain"] = domain


    # -----------------------------------------------------
    # Ignore IP addresses
    # -----------------------------------------------------

    if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        domain
    ):

        return result


    domain_name = get_domain_name(domain)


    # -----------------------------------------------------
    # Compare with known brands
    # -----------------------------------------------------

    for brand in KNOWN_BRANDS:

        # Exact match = legitimate brand name
        if domain_name.lower() == brand:

            continue


        # Normalize confusing characters
        normalized_domain = normalize_lookalike(
            domain_name
        )

        normalized_brand = normalize_lookalike(
            brand
        )


        score = similarity(
            normalized_domain,
            normalized_brand
        )


        # -------------------------------------------------
        # Strong lookalike
        # -------------------------------------------------

        if score >= 80:

            result["detected"] = True

            result["matched_brand"] = brand

            result["similarity"] = score

            result["reason"] = (
                f"Domain '{domain_name}' "
                f"closely resembles the known "
                f"brand '{brand}' "
                f"({score}% similarity)."
            )

            return result


    return result