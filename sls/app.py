import os
import hmac
import struct
import base64
from datetime import datetime, timedelta
from heapq import heappush, heappop

from flask import Flask, request, abort, render_template

from . import bp

app = Flask(__name__)
app.register_blueprint(bp.mod)

SECRETS = {}
# Priority queue of secrets-to-expire
EXPIRE = []
