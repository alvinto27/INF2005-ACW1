"""Flask application factory for the localhost steganography GUI."""

from __future__ import annotations

from flask import Flask


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
    return app
