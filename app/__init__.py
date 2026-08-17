"""Flask application factory. QRadar's app framework loads this package."""

from flask import Flask
from qpylib import qpylib

from . import db


def create_app() -> Flask:
    qpylib.create_log()

    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    with app.app_context():
        try:
            db.init_schema()
        except Exception as error:
            qpylib.log("socai: schema init failed: {}".format(error), level="ERROR")

    from .views.queue import queuebp
    from .views.admin import adminbp

    app.register_blueprint(queuebp, url_prefix="/queue")
    app.register_blueprint(adminbp, url_prefix="/admin")

    qpylib.log("socai: flask app ready")
    return app
