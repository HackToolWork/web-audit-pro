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
