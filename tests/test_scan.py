from secret_guard import has_findings, scan_file, scan_text


def test_scan_text_returns_redacted_findings():
    findings = scan_text(
        "api_key=sk-12345678901234567890\n"
        "host=93.184.216.34:45678\n"
        "placeholder=your-api-key\n",
        path=".env",
        salt=b"fixed-salt",
    )

    assert has_findings(findings)
    assert [(item.category, item.path, item.line, item.key) for item in findings] == [
        ("network", ".env", 2, "host"),
        ("secret", ".env", 1, "api_key"),
    ]
    assert all("sk-" not in item.fingerprint for item in findings)
    assert all("93.184" not in item.fingerprint for item in findings)


def test_scan_text_ignores_non_sensitive_text():
    assert scan_text("normal_key=value\nmax_tokens=1024", salt=b"fixed-salt") == []


def test_scan_file_scans_text_files(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    findings = scan_file(config_path, salt=b"fixed-salt")

    assert len(findings) == 1
    assert findings[0].path == config_path.as_posix()
    assert findings[0].line == 1


def test_scan_file_skips_binary_and_oversized_files(tmp_path):
    binary_path = tmp_path / "binary.bin"
    large_path = tmp_path / "large.txt"
    binary_path.write_bytes(b"abc\x00sk-12345678901234567890")
    large_path.write_text("api_key=sk-12345678901234567890", encoding="utf-8")

    assert scan_file(binary_path, salt=b"fixed-salt") == []
    assert scan_file(large_path, salt=b"fixed-salt", max_text_bytes=4) == []
