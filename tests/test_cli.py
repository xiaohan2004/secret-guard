from secret_guard.cli import main


def test_cli_redacts_secret_text(capsys):
    exit_code = main(["api_key=sk-12345678901234567890"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "[secret hidden]" in output
    assert "sk-12345678901234567890" not in output
