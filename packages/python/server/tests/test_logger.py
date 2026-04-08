"""Tests for structured server logging."""

from starfish_server.logger import ConsoleLogger, JsonLogger, NoopLogger, LogEntry


def test_console_logger_outputs(capsys):
    logger = ConsoleLogger("info")
    logger.log(LogEntry(level="info", message="hello"))
    captured = capsys.readouterr()
    assert "hello" in captured.out


def test_console_logger_filters_below_min_level(capsys):
    logger = ConsoleLogger("warn")
    logger.log(LogEntry(level="info", message="skip"))
    captured = capsys.readouterr()
    assert captured.out == ""


def test_json_logger_outputs_json(capsys):
    logger = JsonLogger("info")
    logger.log(LogEntry(level="info", message="test", extra={"key": "val"}))
    captured = capsys.readouterr()
    assert '"message": "test"' in captured.out or '"message":"test"' in captured.out


def test_noop_logger(capsys):
    logger = NoopLogger()
    logger.log(LogEntry(level="error", message="silent"))
    captured = capsys.readouterr()
    assert captured.out == ""
