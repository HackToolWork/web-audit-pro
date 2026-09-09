from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_install_script_is_present_and_executable():
    script = ROOT / "install.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111
    assert "set -Eeuo pipefail" in script.read_text(encoding="utf-8")


def test_docker_packaging_files_are_present():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "FROM python:3.13-slim AS builder" in dockerfile
    assert 'USER webaudit' in dockerfile
    assert 'ENTRYPOINT ["web-audit"]' in dockerfile
    assert 'WEB_AUDIT_VULN_DB=/app/reports/vulndb.sqlite3' in dockerfile
    assert "__pycache__" in ignore
    assert "reports" in ignore


def test_makefile_has_core_quality_targets():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("test", "lint", "compile", "check", "build", "docker-build"):
        assert f"{target}:" in makefile


def test_installer_refuses_to_replace_unrelated_symlink():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'current_target="$(readlink -f "$BIN_PATH")"' in script
    assert "refusing to replace it" in script


def test_installer_does_not_upgrade_system_pip():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'pip install --upgrade pip' not in script


def test_hatch_package_selection_does_not_duplicate_package_data():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.hatch.build.targets.wheel.force-include]" not in pyproject
    assert 'packages = ["web_audit"]' in pyproject
    resource = ROOT / "web_audit" / "data" / "cms_fingerprints.json"
    assert resource.is_file() and resource.stat().st_size > 0


def test_project_version_is_consistent():
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = pyproject["project"]["version"]

    init_source = (ROOT / "web_audit" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{declared}"' in init_source


def test_makefile_python_version_guard_is_valid():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert 'sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")' in makefile
    assert "raise SystemExit('Python 3.11+ is required') if" not in makefile


def test_makefile_bootstraps_active_or_repository_venv():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "VENV_DIR := $(if $(VIRTUAL_ENV),$(VIRTUAL_ENV),$(CURDIR)/.venv)" in makefile
    assert "PYTEST := $(PYTHON) -m pytest" in makefile
    assert "$(PYTHON) -m compileall -q web_audit tests" in makefile
    assert "$(MAKE) install-dev" in makefile
    assert "command -v python3" in makefile
    assert "BUILD := $(PYTHON) -m build" in makefile
    assert "/usr/bin/python3" not in makefile


def test_makefile_does_not_use_bare_python_launcher():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "python -m pytest" not in makefile
    assert "python -m compileall" not in makefile
    assert "python -m build" not in makefile
    assert "python3 -m venv .venv" in makefile


def test_installer_reports_runtime_and_dev_workflow():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'Runtime environment: $VENV_PATH' in script
    assert 'make test' in script
    assert 'make check' in script


def test_repository_has_standard_contributing_markdown_filename():
    root = ROOT / "CONTRIBUTING.md"
    assert root.is_file()
    assert not (ROOT / "CONTRIBUTING.m\nd").exists()


def test_readme_uses_current_installation_workflow():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "sudo ./install.sh" in readme
    assert "source .venv-system/bin/activate" not in readme


def test_pinned_runtime_and_build_dependencies():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    for line in requirements.splitlines():
        if line and not line.startswith("#"):
            assert "==" in line
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'hatchling==1.32.0' in pyproject
    import re
    match = re.search(r'version = \"([^\"]+)\"', pyproject)
    assert match
    from web_audit import __version__
    assert match.group(1) == __version__


def test_config_example_is_present():
    example = ROOT / "web-audit.toml.example"
    assert example.is_file()
    text = example.read_text(encoding="utf-8")
    assert "[report]" in text
    assert 'company = "Security Assessment Team"' in text


def test_no_stale_release_version_strings_in_tests():
    for test_file in (ROOT / "tests").glob("*.py"):
        if test_file.name == "test_packaging.py":
            continue
        text = test_file.read_text(encoding="utf-8")
        assert "4.3.8" not in text
        assert "4.3.9" not in text


def test_makefile_checks_pytest_before_running_tests():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "require-pytest: ensure-dev" in makefile
    assert "import pytest" in makefile
    assert "Pytest is missing in the selected virtual environment." in makefile


def test_makefile_quality_targets_do_not_require_unrelated_tools():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "test: require-pytest" in makefile
    assert "lint: require-ruff" in makefile
    assert "build: require-build" in makefile
    assert "test: check-python" not in makefile


def test_pinned_development_dependencies():
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    for line in requirements.splitlines():
        if line and not line.startswith("-") and not line.startswith("#"):
            assert "==" in line


def test_makefile_active_environment_does_not_auto_install_missing_tools():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "Pytest is missing in the selected virtual environment." in makefile
    assert "pip install -r requirements-dev.txt" in makefile
    assert 'if [ -n "$(VIRTUAL_ENV)" ]' in makefile


def test_canonical_project_name_is_unversioned_and_portable():
    from web_audit import PROJECT_NAME
    assert PROJECT_NAME == "web-audit-pro"
    assert PROJECT_NAME.lower() == PROJECT_NAME
    assert not any(ch.isdigit() for ch in PROJECT_NAME)


def test_repository_contains_portable_home_path_logic():
    text = (ROOT / "web_audit" / "config.py").read_text(encoding="utf-8")
    assert "Path.home()" in text
    assert "/home/" not in text
