from web_audit.scope import load_scope, target_in_scope


def test_scope_supports_exact_and_wildcard_hosts(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("# bounty scope\nexample.com\n*.api.example.org\n", encoding="utf-8")
    scope = load_scope(path)
    assert target_in_scope("https://example.com", scope)
    assert target_in_scope("https://foo.api.example.org", scope)
    assert not target_in_scope("https://example.net", scope)
    assert not target_in_scope("https://api.example.org.evil.test", scope)
