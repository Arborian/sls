from flask import Flask

from . import bp

app = Flask(__name__)
app.register_blueprint(bp.mod)
