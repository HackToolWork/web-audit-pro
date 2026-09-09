from web_audit.logging import configure_logging


def test_rotating_log_handler_keeps_log_bounded(tmp_path):
    path = tmp_path / "scanner.log"
    configure_logging(path, max_bytes=100, backup_count=2)
    import logging

    logger = logging.getLogger("test")
    for _ in range(30):
        logger.info("x" * 50)
    assert path.exists()
    assert any(tmp_path.glob("scanner.log.*"))
