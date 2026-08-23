import hashlib
import re

import requests
from zxcvbn import zxcvbn


HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/"
HIBP_EMAIL_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"


def check_password_strength(password):
    result = zxcvbn(password)

    score = result.get("score", 0)

    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very Strong"
    }

    suggestions = result.get("feedback", {}).get(
        "suggestions",
        []
    )

    warning = result.get("feedback", {}).get(
        "warning",
        ""
    )

    return {
        "score": score,
        "label": labels.get(score, "Unknown"),
        "guesses": result.get("guesses"),
        "crack_time": result.get("crack_times_display", {}).get(
            "offline_slow_hashing_1e4_per_second",
            "Unknown"
        ),
        "suggestions": suggestions,
        "warning": warning
    }


def check_password_breach(password):
    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    headers = {
        "User-Agent": "ProStackHub-Password-Breach-Checker",
        "Add-Padding": "true"
    }

    try:
        response = requests.get(
            HIBP_PASSWORD_URL + prefix,
            headers=headers,
            timeout=15
        )

        response.raise_for_status()

        for line in response.text.splitlines():

            parts = line.strip().split(":")

            if len(parts) != 2:
                continue

            returned_suffix = parts[0]
            count = int(parts[1])

            if returned_suffix.upper() == suffix:
                return {
                    "breached": True,
                    "count": count
                }

        return {
            "breached": False,
            "count": 0
        }

    except requests.RequestException as error:

        return {
            "breached": False,
            "count": 0,
            "error": str(error)
        }


def check_email_breach(email, api_key):
    email = email.strip().lower()

    if not email:
        return {
            "error": "Email address is required."
        }

    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):
        return {
            "error": "Please enter a valid email address."
        }

    if not api_key:
        return {
            "error": (
                "HIBP API key is not configured. "
                "Email breach lookup requires an HIBP API key."
            )
        }

    headers = {
        "hibp-api-key": api_key,
        "user-agent": "ProStackHub-Password-Breach-Checker"
    }

    try:

        response = requests.get(
            HIBP_EMAIL_URL + requests.utils.quote(
                email,
                safe=""
            ),
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "breached": False,
                "breaches": []
            }

        response.raise_for_status()

        breaches = response.json()

        return {
            "breached": True,
            "breaches": [
                {
                    "name": breach.get("Name"),
                    "title": breach.get("Title"),
                    "domain": breach.get("Domain"),
                    "date": breach.get("BreachDate")
                }
                for breach in breaches
            ]
        }

    except requests.RequestException as error:

        return {
            "error": str(error)
        }