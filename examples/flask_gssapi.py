"""Minimal Flask Kerberos PAC demo. One-round-trip HTTP Negotiate only.

Run with KRB5_KTNAME pointing to a keytab containing HTTP/<hostname>@REALM:
    pip install -e '.[gssapi]' flask
    export KRB5_KTNAME=/path/to/http.keytab
    export KERBEROS_HOSTNAME=service.example.com
    flask --app examples/flask_gssapi.py run --host 127.0.0.1

Use a TLS-enabled reverse proxy in front of this example. Do not run Flask's
built-in development server as a public production service.
"""

import base64
import binascii
import os

import gssapi
from flask import Flask, jsonify, request

from pac_decoder import PACDecodeError
from pac_decoder.gssapi_helpers import PACAttributeError, decode_completed_context

app = Flask(__name__)

# Configure the service name explicitly; do not derive it from HTTP Host.
HOSTNAME = os.environ["KERBEROS_HOSTNAME"]
SERVICE = gssapi.Name(f"HTTP@{HOSTNAME}", name_type=gssapi.NameType.hostbased_service)
CREDS = gssapi.Credentials(name=SERVICE, usage="accept")


def challenge(token=None):
    value = "Negotiate"
    if token:
        value += " " + base64.b64encode(token).decode("ascii")
    return ("Kerberos authentication required", 401, {"WWW-Authenticate": value,
                                                        "Cache-Control": "no-store"})


@app.get("/pac")
def pac():
    header = request.headers.get("Authorization", "")
    scheme, sep, encoded = header.partition(" ")
    if scheme.lower() != "negotiate" or not sep or not encoded:
        return challenge()
    try:
        incoming = base64.b64decode(encoded.strip(), validate=True)
    except (binascii.Error, ValueError):
        return ("Invalid Negotiate token", 400)
    if not incoming or len(incoming) > 1024 * 1024:
        return ("Invalid Negotiate token size", 400)

    # Fresh context: sufficient for the usual one-round-trip Kerberos HTTP
    # exchange. Additional rounds require server-side stateful contexts.
    ctx = gssapi.SecurityContext(creds=CREDS, usage="accept")
    try:
        outgoing = ctx.step(incoming)
    except gssapi.exceptions.GSSError:
        return challenge()
    if not ctx.complete:
        # Do not pretend that a new request with a fresh context can resume
        # this one. This minimal demo intentionally supports one round only.
        return ("Multi-step negotiation is not supported by this demo", 501)
    try:
        info = decode_completed_context(ctx)
    except (PACAttributeError, PACDecodeError):
        return ("Authenticated PAC unavailable or invalid", 403)

    # Do not use unvalidated client-supplied identity headers in place of PAC.
    response = jsonify({"sid": info["sid"], "groups": info["groups"]})
    response.headers["Cache-Control"] = "no-store"
    if outgoing:
        response.headers["WWW-Authenticate"] = "Negotiate " + base64.b64encode(outgoing).decode("ascii")
    return response
