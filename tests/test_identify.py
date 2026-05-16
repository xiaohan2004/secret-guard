from secret_guard import is_sensitive_key, normalize_key_name


def test_normalize_key_name_removes_case_and_separators():
    assert normalize_key_name("Api-Key.Value") == "apikeyvalue"


def test_is_sensitive_key_matches_common_variants():
    assert is_sensitive_key("apiKey")
    assert is_sensitive_key("xxxxxxapikey")
    assert is_sensitive_key("access-token")
    assert is_sensitive_key("private.key")
    assert is_sensitive_key("clientSecret")


def test_is_sensitive_key_supports_extra_sensitive_keys():
    assert is_sensitive_key("tenant_id", extra_sensitive_keys={"tenant_id"})
    assert is_sensitive_key("tenant-id", extra_sensitive_keys={"tenant_id"})


def test_is_sensitive_key_ignores_non_sensitive_names():
    assert not is_sensitive_key("normal_key")
    assert not is_sensitive_key("max_tokens")
