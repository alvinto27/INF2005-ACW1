"""Flask application factory for the localhost steganography GUI."""

from __future__ import annotations

from flask import Flask, jsonify
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge


def create_app(test_config: dict | None = None) -> Flask:
    """Create an isolated Flask application instance."""
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=32 * 1024 * 1024,
        JSON_SORT_KEYS=False,
    )

    if test_config:
        app.config.update(test_config)

    from .routes import web

    app.register_blueprint(web)

    @app.errorhandler(RequestEntityTooLarge)
    @app.errorhandler(BadRequest)
    def invalid_upload(error):
        return jsonify(ok=False, verdict="Cannot Verify", message=error.description), error.code

    @app.after_request
    def no_store(response):
        response.headers["Cache-Control"] = "no-store"
        return response
    return app
