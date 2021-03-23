import os
import hmac
import struct
import base64
from datetime import datetime, timedelta
from heapq import heappush, heappop

from flask import Blueprint, request, abort, render_template

mod = Blueprint("sls", __name__)

SECRETS = {}
# Priority queue of secrets-to-expire
EXPIRE = []


class Secret:
    def __init__(self, text, code, attempts):
        self.text = text
        self.code = code
        self.attempts = attempts


@mod.route("/")
def get_home():
    _reap_expired()
    return render_template("home.html")


@mod.route("/secret", methods=["POST"])
def post_secret():
    _reap_expired()
    text = request.form["text"]
    lifetime = int(request.form["lifetime"])
    attempts = int(request.form["attempts"])
    secret_id = _gen_id()
    code = _gen_code()
    SECRETS[secret_id] = secret = Secret(
        text=text, code=code, attempts=attempts
    )
    expiration = datetime.utcnow() + timedelta(seconds=lifetime)
    heappush(EXPIRE, (expiration, secret_id))
    return render_template(
        "new_secret.html", secret_id=secret_id, secret=secret
    )


@mod.route("/secret/<secret_id>")
def get_secret(secret_id):
    _reap_expired()
    return render_template("secret_form.html", secret_id=secret_id)


@mod.route("/secret/<secret_id>", methods=["POST"])
def reveal_secret(secret_id):
    _reap_expired()
    code = request.form["code"]
    secret = _get_secret_or_404(secret_id)
    if not hmac.compare_digest(secret.code, code):
        secret.attempts -= 1
        if secret.attempts <= 0:
            SECRETS.pop(secret_id, None)
            print("Delete secret", secret_id)
        abort(403)
    SECRETS.pop(secret_id, None)
    return render_template("secret_revealed.html", secret=secret)


def _gen_id():
    data = os.urandom(12)
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _gen_code():
    data = os.urandom(4)
    (code_as_int,) = struct.unpack("I", data)
    return str(code_as_int % 1_000_000)


def _reap_expired():
    while EXPIRE:
        expires, secret_id = EXPIRE[0]
        if expires >= datetime.utcnow():
            break
        print("Expire secret", secret_id)
        SECRETS.pop(secret_id, None)
        heappop(EXPIRE)


def _get_secret_or_404(secret_id):
    secret = SECRETS.get(secret_id)
    if secret is None:
        abort(404)
    return secret
