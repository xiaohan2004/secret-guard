from secret_guard import build_rewrite_plan


def test_build_rewrite_plan_defaults_to_dry_run(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text(
        "api_key=sk-12345678901234567890\nnormal=value\n",
        encoding="utf-8",
    )

    plan = build_rewrite_plan(config_path)

    assert plan.has_changes()
    assert plan.changes[0].line == 1
    assert plan.changes[0].key == "api_key"
    assert "[secret hidden]" in plan.rewritten_text
    assert "sk-12345678901234567890" in config_path.read_text(encoding="utf-8")


def test_rewrite_plan_diff_previews_changes(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    diff = build_rewrite_plan(config_path).diff()

    assert "-api_key=[secret original]" in diff
    assert "+api_key=[secret hidden]" in diff
    assert "sk-12345678901234567890" not in diff


def test_build_rewrite_plan_skips_binary_files(tmp_path):
    binary_path = tmp_path / "config.bin"
    binary_path.write_bytes(b"api_key=sk-12345678901234567890\x00")

    assert not build_rewrite_plan(binary_path).has_changes()
