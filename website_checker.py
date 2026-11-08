import socket
import ipaddress
import time
from urllib.parse import urlparse

import requests


def is_private_ip(ip):
    """
    Check whether an IP belongs to a private/local/reserved network.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
        )

    except ValueError:
        return True


def resolve_domain(domain):
    """
    Resolve a domain name to an IP address.
    """

    try:
        ip = socket.gethostbyname(domain)

        return {
            "success": True,
            "ip": ip,
            "private": is_private_ip(ip)
        }

    except socket.gaierror:
        return {
            "success": False,
            "ip": None,
            "private": False
        }


def check_website(url):
    """
    Perform live verification of a website.

    Checks:
    - DNS resolution
    - IP address
    - Private/local IP protection
    - HTTP/HTTPS connectivity
    - HTTP status code
    - Redirects
    - Final URL
    - Response time
    """

    result = {
        "dns_status": "unknown",
        "dns_message": "",
        "ip_address": None,
        "website_status": "unknown",
        "website_message": "",
        "http_status": None,
        "https": False,
        "redirect_count": 0,
        "final_url": None,
        "response_time": None
    }

    # --------------------------------------------------
    # Validate URL
    # --------------------------------------------------

    try:
        parsed = urlparse(url)

        domain = parsed.hostname

        if not domain:
            result["dns_status"] = "failed"
            result["dns_message"] = "Could not extract domain."
            return result

    except Exception:
        result["dns_status"] = "failed"
        result["dns_message"] = "Invalid URL."
        return result

    # --------------------------------------------------
    # DNS CHECK
    # --------------------------------------------------

    dns_result = resolve_domain(domain)

    if not dns_result["success"]:

        result["dns_status"] = "failed"
        result["dns_message"] = "Domain could not be resolved."

        result["website_status"] = "unreachable"
        result["website_message"] = "Website domain does not appear to exist."

        return result

    result["dns_status"] = "success"
    result["dns_message"] = "Domain successfully resolved."

    result["ip_address"] = dns_result["ip"]

    # --------------------------------------------------
    # SECURITY CHECK
    # --------------------------------------------------

    if dns_result["private"]:

        result["website_status"] = "blocked"
        result["website_message"] = (
            "Connection blocked because the address is private or local."
        )

        return result

    # --------------------------------------------------
    # HTTP / HTTPS CHECK
    # --------------------------------------------------

    try:

        start_time = time.time()

        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": "PhishingURLDetectionSystem/1.0"
            }
        )

        end_time = time.time()

        # Response time in milliseconds
        result["response_time"] = round(
            (end_time - start_time) * 1000,
            2
        )

        result["website_status"] = "reachable"

        result["website_message"] = "Website responded successfully."

        result["http_status"] = response.status_code

        result["https"] = response.url.startswith("https://")

        result["final_url"] = response.url

        result["redirect_count"] = len(response.history)

    except requests.exceptions.Timeout:

        result["website_status"] = "timeout"

        result["website_message"] = (
            "Website did not respond within the time limit."
        )

    except requests.exceptions.SSLError:

        result["website_status"] = "ssl_error"

        result["website_message"] = (
            "Secure HTTPS connection could not be established."
        )

    except requests.exceptions.ConnectionError:

        result["website_status"] = "unreachable"

        result["website_message"] = (
            "Could not connect to the website."
        )

    except requests.exceptions.RequestException as error:

        result["website_status"] = "error"

        result["website_message"] = (
            f"Website request failed: {str(error)}"
        )

    return result