from secret_guard import apply_rewrite_plan, build_rewrite_plan, can_rewrite_path


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


def test_apply_rewrite_plan_requires_explicit_in_place(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    plan = build_rewrite_plan(config_path)

    result = apply_rewrite_plan(plan)

    assert not result.changed
    assert "sk-12345678901234567890" in config_path.read_text(encoding="utf-8")


def test_apply_rewrite_plan_writes_backup_and_replaces_value(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    plan = build_rewrite_plan(config_path)

    result = apply_rewrite_plan(plan, in_place=True, backup=True)

    assert result.changed
    assert result.backup_path is not None
    assert "[secret hidden]" in config_path.read_text(encoding="utf-8")
    assert "sk-12345678901234567890" in (tmp_path / "config.env.bak").read_text(encoding="utf-8")


def test_build_rewrite_plan_can_remove_sensitive_values(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")
    plan = build_rewrite_plan(config_path, remove=True)

    assert plan.rewritten_text.replace("\r\n", "\n") == "api_key=\n"


def test_rewrite_only_changes_matched_value_range(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text(
        "prefix=keep\napi_key=sk-12345678901234567890 # keep comment\n",
        encoding="utf-8",
    )
    plan = build_rewrite_plan(config_path)

    assert "prefix=keep" in plan.rewritten_text
    assert "# keep comment" in plan.rewritten_text
    assert "api_key=[secret hidden] # keep comment" in plan.rewritten_text


def test_rewrite_rejects_excluded_paths(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    config_path = git_dir / "config"
    config_path.write_text("api_key=sk-12345678901234567890\n", encoding="utf-8")

    assert not can_rewrite_path(config_path)
    assert not build_rewrite_plan(config_path).has_changes()
