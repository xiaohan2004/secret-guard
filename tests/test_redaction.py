from secret_guard import one_line_preview, redact_text, redact_value


def test_redact_value_masks_sensitive_keys():
    assert redact_value("deepseek_api_key", "real-key") == "[secret hidden]"
    assert redact_value("api-key", "real-key") == "[secret hidden]"


def test_redact_text_masks_inline_secrets_and_url_credentials():
    assert redact_text("api_key=sk-example") == "api_key=[secret hidden]"
    assert redact_text("password:123456") == "password:[secret hidden]"
    assert (
        redact_text("https://user:pass@example.com")
        == "https://user:[secret hidden]@example.com"
    )


def test_redact_value_supports_length_and_single_line_preview():
    value = "line1\nline2\n" + ("x" * 100)
    rendered = redact_value("prompt", value, max_length=20)

    assert "\\n" in rendered
    assert "\n" not in rendered
    assert rendered.endswith("chars total]")


def test_redact_value_supports_custom_replacement_and_ignored_keys():
    assert redact_value("api_key", "real-key", replacement="<hidden>") == "<hidden>"
    assert redact_value("api_key", "real-key", ignored_keys={"api_key"}) == "real-key"


def test_one_line_preview_escapes_newlines_and_backslashes():
    assert one_line_preview("a\\b\nc") == "a\\\\b\\nc"
