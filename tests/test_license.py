from pathlib import Path


def test_project_license_is_apache_2():
    root = Path(__file__).resolve().parents[1]
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    assert "Apache-2.0" in pyproject
    assert 'license = "Apache-2.0"' in pyproject
    assert "Apache License 2.0" in readme
