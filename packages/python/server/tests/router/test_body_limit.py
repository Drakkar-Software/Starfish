"""Direct unit tests for check_body_limit Content-Length branches."""

import json

import pytest
from fastapi.responses import JSONResponse

from starfish_server.router.middleware import check_body_limit


@pytest.mark.parametrize(
    ("content_length", "status_code", "error"),
    [
        (None, None, None),
        ("abc", 400, "Invalid Content-Length"),
        ("1.5", 400, "Invalid Content-Length"),
        ("-1", 400, "Invalid Content-Length"),
        ("100", None, None),
        ("101", 413, "Payload too large"),
    ],
)
def test_check_body_limit_content_length(
    content_length: str | None,
    status_code: int | None,
    error: str | None,
) -> None:
    result = check_body_limit(content_length, 100)
    if status_code is None:
        assert result is None
        return
    assert isinstance(result, JSONResponse)
    assert result.status_code == status_code
    assert json.loads(result.body) == {"error": error}
