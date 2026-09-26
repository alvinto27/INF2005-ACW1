"""Flask application factory for the localhost steganography GUI."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from flask import Flask, Request, Response, current_app, jsonify, request
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge


_UPLOAD_DISK_MARGIN = 1024**3


class WorkDirectoryRequest(Request):
    """Store multipart file parts on the configured work filesystem."""

    def _get_file_stream(
        self,
        total_content_length: int | None,
        content_type: str | None,
        filename: str | None = None,
        content_length: int | None = None,
    ) -> object:
        """Create each upload stream inside STEGO_WORK_DIR, not the system tmpfs."""
        work_dir = Path(current_app.config["STEGO_WORK_DIR"])
        work_dir.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryFile(mode="w+b", dir=work_dir)


def create_app(test_config: dict | None = None) -> Flask:
    """Create an isolated Flask application instance."""
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=None,
        STEGO_WORK_DIR=Path(app.instance_path) / "work",
        STEGO_OUTPUT_DIR=Path(app.instance_path) / "stego-outputs",
        PAYLOAD_OUTPUT_DIR=Path(app.instance_path) / "recovered-payloads",
        JSON_SORT_KEYS=False,
    )

    if test_config:
        app.config.update(test_config)

    app.request_class = WorkDirectoryRequest

    @app.before_request
    def check_upload_disk_space() -> tuple[Response, int] | None:
        """Reject uploads that cannot fit with a one-GiB free-space margin."""
        if request.method != "POST" or request.endpoint not in {"web.encode", "web.decode"}:
            return None
        content_length = request.content_length
        if content_length is None:
            return None
        work_dir = Path(current_app.config["STEGO_WORK_DIR"])
        work_dir.mkdir(parents=True, exist_ok=True)
        available = max(shutil.disk_usage(work_dir).free - _UPLOAD_DISK_MARGIN, 0)
        if content_length > available:
            return jsonify(
                ok=False,
                error="upload is larger than the free disk space allows",
            ), 413
        return None

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
