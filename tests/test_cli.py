import json
import os
import sqlite3
import subprocess
import sys

from secret_guard.cli import main


def test_cli_redact_command_redacts_secret_text(capsys):
    exit_code = main(["redact", "api_key=sk-12345678901234567890"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "[secret hidden]" in output
    assert "sk-12345678901234567890" not in output


def test_cli_module_entrypoint_shows_help():
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-m", "secret_guard.cli", "--help"],
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0
    assert "usage: secret-guard" in result.stdout


def test_cli_scan_outputs_safe_json_findings(tmp_path, capsys):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    exit_code = main(["scan", str(config_path), "--json"])

    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    findings = report["findings"]
    assert report["skipped"] == []
    assert findings[0]["category"] == "secret"
    assert findings[0]["path"] == config_path.as_posix()
    assert findings[0]["line"] == 1
    assert findings[0]["key"] == "api_key"
    assert "sk-12345678901234567890" not in json.dumps(findings)


def test_cli_scan_can_fail_when_findings_exist(tmp_path, capsys):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    exit_code = main(["scan", str(config_path), "--fail-on-findings"])

    assert exit_code == 1
    assert "fingerprint=" in capsys.readouterr().out


def test_cli_scan_reports_skipped_files_in_text_and_json(tmp_path, capsys):
    huge_path = tmp_path / "huge.txt"
    huge_path.write_bytes(b"abcde")

    text_exit_code = main(["scan", str(tmp_path), "--max-scan-bytes", "4"])
    text_output = capsys.readouterr().out

    json_exit_code = main(["scan", str(tmp_path), "--max-scan-bytes", "4", "--json"])
    json_output = json.loads(capsys.readouterr().out)

    assert text_exit_code == 0
    assert "skipped" in text_output
    assert "reason=too_large" in text_output
    assert json_exit_code == 0
    assert json_output["findings"] == []
    assert json_output["skipped"][0]["reason"] == "too_large"


def test_cli_audit_outputs_skill_compatible_report_without_raw_values(tmp_path, capsys):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    exit_code = main(["audit", str(tmp_path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "1、是否存在敏感信息" in output
    assert "2、敏感信息是否进入git提交" in output
    assert "3、是否存在跳过文件" in output
    assert "是" in output
    assert "否" in output
    assert "config.env" in output
    assert "第1行 api_key" in output
    assert "标识" in output
    assert "sk-12345678901234567890" not in output


def test_cli_audit_reports_skipped_files(tmp_path, capsys):
    huge_path = tmp_path / "huge.txt"
    huge_path.write_bytes(b"abcde")

    exit_code = main(["audit", str(tmp_path), "--max-scan-bytes", "4"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "3、是否存在跳过文件" in output
    assert huge_path.as_posix() in output
    assert "too_large" in output


def test_cli_audit_scans_sqlite_key_value_tables(tmp_path, capsys):
    db_path = tmp_path / "config.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("create table settings (key text, value text)")
        conn.execute(
            "insert into settings values (?, ?)",
            ("api_key", "sk-12345678901234567890"),
        )

    exit_code = main(["audit", str(tmp_path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "config.db" in output
    assert "SQLite" not in output
    assert "settings.api_key" in output
    assert "sk-12345678901234567890" not in output


def test_cli_audit_reports_committed_secrets_without_raw_values(tmp_path, capsys):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.env"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add config"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)

    exit_code = main(["audit", str(tmp_path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    history_section = output.split("2、敏感信息是否进入git提交", 1)[1]
    assert "是" in history_section
    assert ":config.env" in history_section
    assert "第1行 api_key" in history_section
    assert "sk-12345678901234567890" not in output


def test_cli_rewrite_defaults_to_dry_run(tmp_path, capsys):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    exit_code = main(["rewrite", str(config_path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "-api_key=[secret original]" in output
    assert "+api_key=[secret hidden]" in output
    assert "sk-12345678901234567890" not in output
    assert "sk-12345678901234567890" in config_path.read_text(encoding="utf-8")


def test_cli_rewrite_apply_with_backup(tmp_path, capsys):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    exit_code = main(["rewrite", str(config_path), "--apply", "--backup"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "changed=True" in output
    assert "backup=" in output
    assert "[secret hidden]" in config_path.read_text(encoding="utf-8")
    assert "sk-12345678901234567890" in (tmp_path / "config.env.bak").read_text(encoding="utf-8")
