from secret_guard import (
    SensitiveKind,
    classify_key_name,
    classify_value,
    is_high_confidence_secret_value,
    is_common_public_ip,
    is_interesting_public_ip,
    is_public_ip,
    is_sensitive_key,
    is_unusual_public_endpoint,
    looks_like_placeholder,
    normalize_key_name,
    parse_assignment,
    parse_ip_port,
)


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


def test_is_sensitive_key_supports_ignored_keys():
    assert not is_sensitive_key("api_key", ignored_keys={"api_key"})
    assert not is_sensitive_key("api-key", ignored_keys={"api_key"})
    assert classify_key_name("api_key", ignored_keys={"api_key"}) is None


def test_is_sensitive_key_ignores_non_sensitive_names():
    assert not is_sensitive_key("normal_key")
    assert not is_sensitive_key("max_tokens")


def test_parse_assignment_supports_equals_and_colon():
    equals = parse_assignment("api_key=sk-example")
    colon = parse_assignment("password: 'secret value'")

    assert equals is not None
    assert equals.key == "api_key"
    assert equals.value == "sk-example"
    assert equals.operator == "="

    assert colon is not None
    assert colon.key == "password"
    assert colon.value == "secret value"
    assert colon.operator == ":"
    assert colon.quote == "'"


def test_parse_assignment_ignores_non_assignments():
    assert parse_assignment("not an assignment") is None


def test_is_high_confidence_secret_value_matches_known_tokens():
    assert is_high_confidence_secret_value("sk-12345678901234567890")
    assert is_high_confidence_secret_value("AKIA1234567890ABCDEF")
    assert is_high_confidence_secret_value("ghp_1234567890abcdefABCDEF1234567890abcd")
    assert is_high_confidence_secret_value("-----BEGIN PRIVATE KEY-----")


def test_is_high_confidence_secret_value_ignores_plain_text():
    assert not is_high_confidence_secret_value("not-a-secret")
    assert not is_high_confidence_secret_value("test-key")


def test_public_ip_helpers_identify_interesting_public_ips():
    assert is_public_ip("93.184.216.34")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("not-an-ip")

    assert is_common_public_ip("8.8.8.8")
    assert not is_interesting_public_ip("8.8.8.8")
    assert is_interesting_public_ip("93.184.216.34")


def test_public_endpoint_helpers_identify_unusual_ports():
    endpoint = parse_ip_port("93.184.216.34:45678")

    assert endpoint is not None
    assert endpoint.ip == "93.184.216.34"
    assert endpoint.port == 45678

    assert is_unusual_public_endpoint("93.184.216.34:45678")
    assert not is_unusual_public_endpoint("93.184.216.34:443")
    assert not is_unusual_public_endpoint("93.184.216.34:45678", common_ports={45678})
    assert not is_unusual_public_endpoint("8.8.8.8:45678")
    assert not is_unusual_public_endpoint("127.0.0.1:45678")
    assert not is_unusual_public_endpoint("not-an-endpoint")


def test_classify_key_name_groups_sensitive_fields():
    assert classify_key_name("api_key") == SensitiveKind.SECRET
    assert classify_key_name("user_email") == SensitiveKind.ACCOUNT
    assert classify_key_name("normal_key") is None


def test_classify_value_groups_sensitive_values():
    assert classify_value("sk-12345678901234567890") == SensitiveKind.SECRET
    assert classify_value("93.184.216.34") == SensitiveKind.NETWORK
    assert classify_value("93.184.216.34:45678") == SensitiveKind.NETWORK
    assert classify_value("8.8.8.8") is None


def test_looks_like_placeholder_filters_common_placeholders():
    assert looks_like_placeholder("your-api-key")
    assert looks_like_placeholder("${API_KEY}")
    assert looks_like_placeholder("xxxx")
    assert not looks_like_placeholder("sk-real-value-123456")
    assert classify_value("test-key") is None
