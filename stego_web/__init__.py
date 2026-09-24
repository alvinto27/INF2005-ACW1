"""Flask application factory for the localhost steganography GUI."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, current_app, jsonify
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge


def create_app(test_config: dict | None = None) -> Flask:
    """Create an isolated Flask application instance."""
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=256 * 1024 * 1024,
        STEGO_OUTPUT_DIR=Path(app.instance_path) / "stego-outputs",
        PAYLOAD_OUTPUT_DIR=Path(app.instance_path) / "recovered-payloads",
        JSON_SORT_KEYS=False,
    )

    if test_config:
        app.config.update(test_config)

    from .routes import web

    app.register_blueprint(web)

    @app.errorhandler(RequestEntityTooLarge)
    @app.errorhandler(BadRequest)
    def invalid_upload(
        error: BadRequest | RequestEntityTooLarge,
    ) -> tuple[Response, int]:
        """Keep malformed and oversized request errors JSON-readable."""
        return jsonify(ok=False, verdict="Cannot Verify", message=error.description), error.code

    @app.errorhandler(Exception)
    def unexpected_error(
        error: Exception,
    ) -> Response | HTTPException | tuple[Response, int]:
        """Log unexpected failures and return a safe JSON response."""
        if isinstance(error, HTTPException):
            return error
        current_app.logger.exception("Unexpected error while handling request")
        return jsonify(
            ok=False,
            verdict="Cannot Verify",
            error="internal server error",
        ), 500

    @app.after_request
    def no_store(response: Response) -> Response:
        """Prevent browsers from caching uploaded or recovered payload data."""
        response.headers["Cache-Control"] = "no-store"
        return response
    return app
