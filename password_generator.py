import secrets
import string


def generate_password(
    length=20,
    use_upper=True,
    use_lower=True,
    use_digits=True,
    use_symbols=True
):
    groups = []

    if use_upper:
        groups.append(string.ascii_uppercase)

    if use_lower:
        groups.append(string.ascii_lowercase)

    if use_digits:
        groups.append(string.digits)

    if use_symbols:
        groups.append("!@#$%^&*()-_=+[]{}<>?")

    if not groups:
        raise ValueError(
            "At least one character group is required."
        )

    if length < len(groups):
        raise ValueError(
            "Password length is too short."
        )

    password = [
        secrets.choice(group)
        for group in groups
    ]

    all_characters = "".join(groups)

    while len(password) < length:
        password.append(
            secrets.choice(all_characters)
        )

    secrets.SystemRandom().shuffle(password)

    return "".join(password)