import json

from secret_guard.cli import main


def test_cli_redact_command_redacts_secret_text(capsys):
    exit_code = main(["redact", "api_key=sk-12345678901234567890"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "[secret hidden]" in output
    assert "sk-12345678901234567890" not in output


def test_cli_scan_outputs_safe_json_findings(tmp_path, capsys):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    exit_code = main(["scan", str(config_path), "--json"])

    assert exit_code == 0
    findings = json.loads(capsys.readouterr().out)
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
