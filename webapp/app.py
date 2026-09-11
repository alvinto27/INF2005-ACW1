"""Flask application factory and command-line entry point."""

from flask import Flask

from .crypto_service import CryptographyService
from .routes import routes


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["CRYPTO_SERVICE"] = CryptographyService()
    app.register_blueprint(routes)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
