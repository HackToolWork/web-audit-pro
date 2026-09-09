import pytest

from web_audit.config import Settings


def test_settings_defaults_validate():
    Settings().validate()


@pytest.mark.parametrize(
    "field,value",
    [("timeout", 0), ("max_size", 0), ("threads", 0), ("retries", -1), ("backoff_factor", -1)],
)
def test_settings_reject_invalid_numbers(field, value):
    settings = Settings()
    setattr(settings, field, value)
    with pytest.raises(ValueError):
        settings.validate()


def test_settings_reject_crlf_paths():
    settings = Settings(paths=("/ok", "/bad\r\nX"))
    with pytest.raises(ValueError):
        settings.validate()


def test_requests_per_second_must_be_positive():
    from web_audit.config import Settings

    settings = Settings(requests_per_second=0)
    try:
        settings.validate()
    except ValueError as exc:
        assert "requests_per_second" in str(exc)
    else:
        raise AssertionError("expected validation failure")


def test_logging_rotation_settings_validate():
    settings = Settings(log_max_bytes=0)
    with pytest.raises(ValueError, match="log_max_bytes"):
        settings.validate()
    settings = Settings(log_backup_count=0)
    with pytest.raises(ValueError, match="log_backup_count"):
        settings.validate()


def test_toml_config_loads_and_cli_precedence(tmp_path):
    from argparse import Namespace

    from web_audit.config import apply_cli_config

    cfg = tmp_path / "web-audit.toml"
    cfg.write_text(
        '[scan]\nthreads=12\noutput_dir="reports-x"\n'
        '[report]\ncompany="Configured Security"\n'
        "[features]\ntui=true\n",
        encoding="utf-8",
    )
    ns = Namespace(
        config=cfg,
        threads=None,
        output_dir=None,
        company=None,
        tui=None,
    )
    apply_cli_config(ns, cfg)
    assert ns.threads == 12
    assert ns.output_dir == str((cfg.parent / "reports-x").resolve())
    assert ns.company == "Configured Security"
    assert ns.tui is True


def test_toml_config_rejects_unknown_options(tmp_path):
    from argparse import Namespace

    from web_audit.config import apply_cli_config

    cfg = tmp_path / "web-audit.toml"
    cfg.write_text("[scan]\nwat = true\n", encoding="utf-8")
    ns = Namespace(config=cfg)
    with pytest.raises(ValueError, match="unknown config option"):
        apply_cli_config(ns, cfg)


def test_config_relative_paths_resolve_from_config_directory(tmp_path):
    from argparse import Namespace

    from web_audit.config import apply_cli_config

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    cfg = cfg_dir / "web-audit.toml"
    cfg.write_text('[scan]\noutput_dir="reports"\n', encoding="utf-8")
    ns = Namespace(config=cfg, output_dir=None)
    apply_cli_config(ns, cfg)
    assert ns.output_dir == str((cfg_dir / "reports").resolve())


def test_config_cli_value_wins_over_file(tmp_path):
    from argparse import Namespace

    from web_audit.config import apply_cli_config

    cfg = tmp_path / "web-audit.toml"
    cfg.write_text("[scan]\nthreads=12\n", encoding="utf-8")
    ns = Namespace(config=cfg, threads=4)
    apply_cli_config(ns, cfg)
    assert ns.threads == 4


def test_config_rejects_string_for_integer_option(tmp_path):
    from argparse import Namespace

    from web_audit.config import apply_cli_config

    cfg = tmp_path / "web-audit.toml"
    cfg.write_text('[scan]\nthreads="15"\n', encoding="utf-8")
    ns = Namespace(config=cfg, threads=None)
    with pytest.raises(ValueError, match="threads"):
        apply_cli_config(ns, cfg)


def test_cli_type_coercion_normalizes_numeric_strings():
    from argparse import Namespace

    from web_audit.config import coerce_cli_types

    ns = Namespace(threads="15", timeout="2.5", requests_per_second="3", nvd_timeout="4")
    coerce_cli_types(ns)
    assert ns.threads == 15
    assert ns.timeout == 2.5
    assert ns.requests_per_second == 3.0
    assert ns.nvd_timeout == 4.0
