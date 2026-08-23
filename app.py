import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify

from checker import (
    check_password_strength,
    check_password_breach,
    check_email_breach
)

from password_generator import generate_password


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

load_dotenv(
    os.path.join(BASE_DIR, ".env"),
    override=True
)

HIBP_API_KEY = os.getenv("HIBP_API_KEY")


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check-password", methods=["POST"])
def check_password():

    password = request.form.get(
        "password",
        ""
    )

    if not password:
        return jsonify({
            "error": "Password is required."
        }), 400

    strength = check_password_strength(
        password
    )

    breach = check_password_breach(
        password
    )

    # Never return the password itself.
    return jsonify({
        "strength": strength,
        "breach": breach
    })


@app.route("/check-email", methods=["POST"])
def check_email():

    email = request.form.get(
        "email",
        ""
    )

    result = check_email_breach(
        email,
        HIBP_API_KEY
    )

    return jsonify(result)


@app.route("/generate-password")
def generate():

    try:

        length = int(
            request.args.get(
                "length",
                20
            )
        )

        length = max(
            12,
            min(length, 64)
        )

        password = generate_password(
            length=length
        )

        return jsonify({
            "password": password
        })

    except ValueError:

        return jsonify({
            "error": "Invalid password length."
        }), 400


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5002,
        debug=False
    )