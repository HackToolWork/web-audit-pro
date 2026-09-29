import io

import pytest

from web_audit import cli


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"LANG": "ru_RU.UTF-8"}, "ru"),
        ({"LANG": "en_US.UTF-8"}, "en"),
        ({"LANG": "ru_RU.UTF-8", "LC_ALL": "C"}, "en"),
        ({"LANG": "en_US.UTF-8", "LC_MESSAGES": "ru_RU.UTF-8"}, "ru"),
        ({}, "en"),
    ],
)
def test_system_lang(monkeypatch, env, expected):
    for name in ("LANG", "LC_ALL", "LC_MESSAGES"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert cli._system_lang() == expected


def test_explicit_lang_overrides_locale(monkeypatch):
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    args, _ = cli._prepare_args(cli.build_parser().parse_args(["example.com", "--lang", "en"]))
    assert args.lang == "en"
    args, _ = cli._prepare_args(cli.build_parser().parse_args(["example.com"]))
    assert args.lang == "ru"


class _TTY(io.StringIO):
    def isatty(self):
        return True


def _interactive(monkeypatch, answer):
    monkeypatch.setattr(cli.sys, "stdin", _TTY())
    monkeypatch.setattr(cli.sys, "stdout", _TTY())
    prompts = []

    def fake_input(prompt):
        prompts.append(prompt)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr("builtins.input", fake_input)
    return prompts


@pytest.mark.parametrize("answer", ["y", "YES", "да", " Д "])
def test_interactive_confirmation_accepts(monkeypatch, answer):
    prompts = _interactive(monkeypatch, answer)
    assert cli._confirm_authorization("https://www.example.com/", "ru") is True
    assert prompts == [
        "Вы владелец сайта www.example.com или у вас есть разрешение на его проверку? [y/N]: "
    ]


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe", EOFError()])
def test_interactive_confirmation_defaults_to_no(monkeypatch, answer):
    _interactive(monkeypatch, answer)
    assert cli._confirm_authorization("example.com", "en") is False


def test_non_interactive_run_never_prompts(monkeypatch):
    def fail(prompt):
        raise AssertionError("must not prompt without a terminal")

    monkeypatch.setattr("builtins.input", fail)
    assert cli._confirm_authorization("example.com", "en") is False
    assert cli.main(["example.com"]) == 2


def test_declined_prompt_refuses_scan(monkeypatch):
    _interactive(monkeypatch, "n")
    assert cli.main(["example.com"]) == 2
    assert "Refusing to scan" in cli.sys.stdout.getvalue()


def test_every_message_has_both_languages_with_the_same_fields():
    from string import Formatter

    from web_audit.i18n import MESSAGES, SEVERITY_LABELS

    def fields(text):
        return {name for _, name, _, _ in Formatter().parse(text) if name}

    for key, texts in MESSAGES.items():
        assert set(texts) == {"en", "ru"}, key
        assert fields(texts["en"]) == fields(texts["ru"]), key
    assert set(SEVERITY_LABELS["ru"]) == set(SEVERITY_LABELS["en"])


def _scan_output(monkeypatch, tmp_path, capsys, *extra):
    from datetime import UTC, datetime

    from web_audit.models import CheckResult, Finding

    class Scanner:
        def __init__(self, settings, proxy=None):
            pass

        def scan_target(self, target, progress_callback=None):
            finding = Finding(
                "headers.csp", "Content Security Policy is missing", "low", "h", "e", "r"
            )
            return [
                CheckResult(
                    url=target + "/",
                    status=200,
                    size=0,
                    elapsed_ms=1.0,
                    scanned_at=datetime.now(UTC),
                    findings=(finding,),
                )
            ]

    opened = []
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(cli, "Scanner", Scanner)
    monkeypatch.setattr(cli, "_open_report", lambda path: opened.append(path) or True)
    code = cli.main(
        ["https://example.com", "--yes-i-am-authorized", "--paths", "/", "--no-dns"]
        + ["--output-dir", str(tmp_path), *extra]
    )
    return code, capsys.readouterr().out, opened


def test_russian_terminal_output(monkeypatch, tmp_path, capsys):
    code, out, _ = _scan_output(monkeypatch, tmp_path, capsys, "--lang", "ru")
    assert code == 0
    assert "[*] Сайт: https://example.com" in out
    assert "[РЕКОМЕНДУЕТСЯ] Нет политики безопасности контента (CSP) (headers.csp)" in out
    assert "Проверка №1 завершена" in out
    assert "Итог: Серьёзных проблем не найдено" not in out  # TLS check failed offline
    assert "Итог: Явных проблем не найдено, но проверка неполная" in out
    assert "Отчёт для владельца:" in out


def test_english_terminal_output_is_unchanged(monkeypatch, tmp_path, capsys):
    code, out, _ = _scan_output(monkeypatch, tmp_path, capsys)
    assert code == 0
    assert "[LOW] Content Security Policy is missing (headers.csp)" in out
    assert "Scan #1 complete" in out
    assert "Findings=1 | high=0 | medium=0 | low=1 | info=0" in out
    assert "Owner report:" in out


def test_report_opens_only_when_asked_or_on_a_desktop(monkeypatch, tmp_path, capsys):
    _, _, opened = _scan_output(monkeypatch, tmp_path / "default", capsys)
    assert opened == []  # tests are not an interactive desktop session
    _, out, opened = _scan_output(monkeypatch, tmp_path / "forced", capsys, "--open")
    assert len(opened) == 1 and opened[0].name.startswith("owner-report-")
    assert "[*] Opened report:" in out
    monkeypatch.setattr(cli, "_desktop_session", lambda: True)
    _, _, opened = _scan_output(monkeypatch, tmp_path / "desktop", capsys)
    assert len(opened) == 1
    _, _, opened = _scan_output(monkeypatch, tmp_path / "disabled", capsys, "--no-open")
    assert opened == []


def test_desktop_session_requires_a_display_on_linux(monkeypatch):
    monkeypatch.setattr(cli.sys, "stdin", _TTY())
    monkeypatch.setattr(cli.sys, "stdout", _TTY())
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert cli._desktop_session() is False
    monkeypatch.setenv("DISPLAY", ":0")
    assert cli._desktop_session() is True


def test_config_error_uses_system_language(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    config = tmp_path / "bad.toml"
    config.write_text("[scan]\nthreads = 'many'\n", encoding="utf-8")
    assert cli.main(["example.com", "--config", str(config)]) == 2
    assert "Ошибка конфигурации" in capsys.readouterr().out
