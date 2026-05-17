import os
import sqlite3
import subprocess

from secret_guard import FileKind, classify_file, has_findings, iter_scan_files, scan_file, scan_file_report, scan_git_history, scan_high_confidence_text, scan_path, scan_path_report, scan_sqlite, scan_text


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


def test_scan_text_deduplicates_same_finding():
    findings = scan_text(
        "api_key=sk-12345678901234567890",
        path=".env",
        salt=b"fixed-salt",
    )

    assert len(findings) == 1


def test_scan_file_scans_text_files(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    findings = scan_file(config_path, salt=b"fixed-salt")

    assert len(findings) == 1
    assert findings[0].path == config_path.as_posix()
    assert findings[0].line == 1


def test_scan_file_uses_high_confidence_scan_for_binary_and_oversized_files(tmp_path):
    binary_path = tmp_path / "binary.bin"
    large_path = tmp_path / "large.txt"
    binary_path.write_bytes(b"abc\x00sk-12345678901234567890")
    large_path.write_text("api_key=sk-12345678901234567890", encoding="utf-8")

    binary_findings = scan_file(binary_path, salt=b"fixed-salt")
    large_findings = scan_file(large_path, salt=b"fixed-salt", max_text_bytes=4)

    assert len(binary_findings) == 1
    assert binary_findings[0].path == binary_path.as_posix()
    assert len(large_findings) == 1
    assert large_findings[0].path == large_path.as_posix()


def test_scan_file_streams_large_files_with_overlap(tmp_path):
    large_path = tmp_path / "large.txt"
    large_path.write_bytes(b"prefix\n" + b"x" * 9 + b"sk-12345678901234567890\n")

    report = scan_file_report(
        large_path,
        salt=b"fixed-salt",
        max_text_bytes=4,
        max_scan_bytes=1024,
        chunk_bytes=10,
        overlap_bytes=32,
    )

    assert len(report.findings) == 1
    assert report.findings[0].path == large_path.as_posix()
    assert report.skipped == ()


def test_scan_file_reports_extremely_large_files_as_skipped(tmp_path):
    huge_path = tmp_path / "huge.txt"
    huge_path.write_bytes(b"abcde")

    report = scan_file_report(
        huge_path,
        salt=b"fixed-salt",
        max_text_bytes=2,
        max_scan_bytes=4,
    )

    assert report.findings == ()
    assert len(report.skipped) == 1
    assert report.skipped[0].path == huge_path.as_posix()
    assert report.skipped[0].reason == "too_large"
    assert report.skipped[0].size == os.path.getsize(huge_path)


def test_scan_path_report_collects_skipped_files(tmp_path):
    keep_path = tmp_path / "keep.env"
    huge_path = tmp_path / "huge.txt"
    keep_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    huge_path.write_bytes(b"x" * 100)

    report = scan_path_report(tmp_path, salt=b"fixed-salt", max_scan_bytes=64)

    assert len(report.findings) == 1
    assert [item.path for item in report.skipped] == [huge_path.as_posix()]


def test_scan_high_confidence_text_ignores_sensitive_keys_without_secret_values():
    assert scan_high_confidence_text("api_key=short", salt=b"fixed-salt") == []


def test_scan_path_scans_directory_and_skips_excluded_dirs(tmp_path):
    keep_path = tmp_path / "keep.env"
    ignored_dir = tmp_path / "node_modules"
    ignored_path = ignored_dir / "ignored.env"
    keep_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    ignored_dir.mkdir()
    ignored_path.write_text("api_key=sk-ignored123456789012345\n", encoding="utf-8")

    findings = scan_path(tmp_path, salt=b"fixed-salt")

    assert len(findings) == 1
    assert findings[0].path == keep_path.as_posix()


def test_iter_scan_files_supports_excluded_paths(tmp_path):
    keep_path = tmp_path / "keep.env"
    skip_path = tmp_path / "skip.env"
    keep_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    skip_path.write_text("api_key=sk-ignored123456789012345\n", encoding="utf-8")

    files = list(iter_scan_files(tmp_path, excluded_paths={skip_path}))

    assert keep_path in files
    assert skip_path not in files


def test_classify_file_groups_supported_file_types():
    assert classify_file(".env") == FileKind.CONFIG
    assert classify_file("settings.yaml") == FileKind.CONFIG
    assert classify_file("app.py") == FileKind.CODE
    assert classify_file("openclass.db") == FileKind.SQLITE
    assert classify_file("notes.txt") == FileKind.TEXT


def test_scan_sqlite_scans_key_value_tables(tmp_path):
    db_path = tmp_path / "config.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("create table settings (key text, value text)")
        conn.execute("insert into settings values (?, ?)", ("api_key", "sk-12345678901234567890"))
        conn.execute("insert into settings values (?, ?)", ("normal_key", "value"))
        conn.execute("insert into settings values (?, ?)", ("placeholder", "your-api-key"))

    findings = scan_sqlite(db_path, salt=b"fixed-salt")

    assert len(findings) == 1
    assert findings[0].path == db_path.as_posix()
    assert findings[0].line == 1
    assert findings[0].key == "settings.api_key"
    assert "sk-" not in findings[0].fingerprint


def test_scan_git_history_scans_committed_content(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)
    secret_path = tmp_path / "config.env"
    secret_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.env"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add config"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)

    findings = scan_git_history(tmp_path, salt=b"fixed-salt")

    assert len(findings) == 1
    assert findings[0].category == "secret"
    assert findings[0].path.endswith(":config.env")
    assert findings[0].line == 1
    assert "sk-" not in findings[0].fingerprint
