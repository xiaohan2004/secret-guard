# 使用说明

## 命令行审计

`audit` 是给日常仓库检查和 Codex skill 使用的固定格式报告：

```bash
secret-guard audit .
```

它会输出两部分：

- `1、是否存在敏感信息`
- `2、敏感信息是否进入git提交`

报告只展示文件路径、位置、类别和不可逆标识，不展示原始敏感值。

## 命令行扫描

扫描单个文件或目录：

```bash
secret-guard scan backend/.env
secret-guard scan .
```

输出不会包含原始敏感值，只会包含类别、位置、字段名和不可逆指纹。需要 JSON 时：

```bash
secret-guard scan . --json
```

用于 CI 或提交前检查时，可以让发现敏感信息后返回非零状态码：

```bash
secret-guard scan . --fail-on-findings
```

扫描时可以排除指定路径：

```bash
secret-guard scan . --exclude .venv --exclude node_modules
```

扫描 Git 历史：

```bash
secret-guard scan . --git-history
```

## 命令行脱敏

```bash
secret-guard redact "api_key=replace-with-real-value"
```

默认会把敏感值替换为 `[secret hidden]`。也可以指定占位符：

```bash
secret-guard redact "password=replace-with-real-value" --replacement "[hidden]"
```

## 命令行改写

改写默认是 dry-run，只显示将要修改的 diff，不会写入文件：

```bash
secret-guard rewrite backend/.env
```

确认后再显式写入：

```bash
secret-guard rewrite backend/.env --apply
```

写入前创建备份：

```bash
secret-guard rewrite backend/.env --apply --backup
```

也可以移除敏感值，而不是替换为占位符：

```bash
secret-guard rewrite backend/.env --remove --apply --backup
```

## Python API

```python
from secret_guard import scan_path, redact_text, build_rewrite_plan

findings = scan_path(".")
safe_text = redact_text("api_key=replace-with-real-value")
plan = build_rewrite_plan("backend/.env")

if plan.has_changes():
    print(plan.diff())
```
