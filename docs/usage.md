# 使用说明

本文档说明 `secret-guard` 的命令行用法和 Python API。

`secret-guard` 的所有扫描、审计、脱敏和改写输出都不应该展示原始敏感值。命中结果会使用不可逆指纹或占位符表示敏感内容。

## 安装后使用

本地开发安装：

```bash
pip install -e .
```

安装后可以直接使用命令行入口：

```bash
secret-guard --help
```

在源码仓库内调试，也可以使用模块方式运行：

```bash
python -m secret_guard.cli --help
```

如果没有安装到当前 Python 环境，需要先让 Python 找到 `src` 目录。

PowerShell：

```powershell
$env:PYTHONPATH = "src"
python -m secret_guard.cli --help
```

## 命令总览

```bash
secret-guard audit [path]
secret-guard scan <path>
secret-guard redact <text>
secret-guard rewrite <path>
```

- `audit`：输出固定两段式仓库审计报告，适合人工阅读或 Codex skill 调用。
- `scan`：扫描文件或目录，适合普通命令行检查、JSON 输出和 CI 检查。
- `redact`：对一段命令行文本做内联脱敏。
- `rewrite`：预览或执行本地文件改写。

## audit：仓库审计

`audit` 默认检查工作区和 Git 历史：

```bash
secret-guard audit .
```

不传路径时默认检查当前目录：

```bash
secret-guard audit
```

输出固定包含两部分：

```text
1、是否存在敏感信息
是
- backend/.env
  - 第3行 api_key：密钥/密码，标识 1a2b3c4d5e

2、敏感信息是否进入git提交
否
```

含义：

- 第一部分扫描当前工作区。
- 第二部分扫描当前仓库可达的 Git 提交。
- `是` 表示发现敏感信息。
- `否` 表示没有发现敏感信息。
- `标识` 是本次运行内生成的不可逆短指纹，不是原始值。

`audit` 会额外扫描 SQLite key/value 表，适合替换 `scan-secrets` skill 里的固定报告脚本。

限制单个文本文件完整扫描大小：

```bash
secret-guard audit . --max-text-bytes 1048576
```

## scan：扫描文件或目录

扫描单个文件：

```bash
secret-guard scan backend/.env
```

扫描整个目录：

```bash
secret-guard scan .
```

默认文本输出示例：

```text
secret  backend/.env:3  key=api_key  fingerprint=1a2b3c4d5e
```

字段含义：

- 第一列：敏感类别。
- `path:line`：命中文件和行号。
- `key`：命中的字段名，没有字段名时显示 `-`。
- `fingerprint`：不可逆指纹。

输出 JSON：

```bash
secret-guard scan . --json
```

JSON 输出示例：

```json
[
  {
    "category": "secret",
    "path": "backend/.env",
    "line": 3,
    "fingerprint": "1a2b3c4d5e",
    "key": "api_key"
  }
]
```

扫描 Git 历史：

```bash
secret-guard scan . --git-history
```

排除路径：

```bash
secret-guard scan . --exclude .venv --exclude node_modules
```

命中时返回非零状态码，适合 CI 或提交前检查：

```bash
secret-guard scan . --fail-on-findings
```

限制单个文本文件完整扫描大小：

```bash
secret-guard scan . --max-text-bytes 1048576
```

`scan` 会自动跳过常见依赖目录、缓存目录、二进制文件和过大文件。对二进制或过大文件，只做高置信密钥模式扫描。

## redact：脱敏文本

脱敏一段文本：

```bash
secret-guard redact "api_key=replace-with-real-value"
```

输出：

```text
api_key=[secret hidden]
```

自定义占位符：

```bash
secret-guard redact "password=replace-with-real-value" --replacement "[hidden]"
```

`redact` 会处理常见 `key=value`、`key: value` 片段，以及 URL 中的用户名密码片段。

## rewrite：预览和改写文件

`rewrite` 默认只做 dry-run，显示将要修改的 diff，不写入文件：

```bash
secret-guard rewrite backend/.env
```

diff 中不会展示原始敏感值。原始值会显示为 `[secret original]`：

```diff
-api_key=[secret original]
+api_key=[secret hidden]
```

输出 JSON 改写计划：

```bash
secret-guard rewrite backend/.env --json
```

显式写入文件：

```bash
secret-guard rewrite backend/.env --apply
```

写入前创建 `.bak` 备份：

```bash
secret-guard rewrite backend/.env --apply --backup
```

移除敏感值，而不是替换为占位符：

```bash
secret-guard rewrite backend/.env --remove --apply --backup
```

自定义替换占位符：

```bash
secret-guard rewrite backend/.env --replacement "[redacted]"
```

限制单个文件大小：

```bash
secret-guard rewrite backend/.env --max-text-bytes 1048576
```

`rewrite` 只改写明确命中的赋值范围，不会重写整个文件格式。它会拒绝改写二进制文件、过大文件、依赖目录和 Git 内部目录。

## 输出字段

扫描结果的结构化字段：

- `category`：敏感类别。
  - `secret`：密钥、密码、token、credential 等。
  - `account`：账号类字段，例如 username、account、email。
  - `network`：公网 IP 或公网 IP 加非常见端口。
- `path`：命中文件路径。
- `line`：命中行号。无法定位时可能为 `0`。
- `key`：命中的字段名。没有字段名时为 `null` 或 `-`。
- `fingerprint`：不可逆短指纹，用来区分同一次扫描中的不同命中。

指纹不会包含原始值，也不能还原原始值。默认情况下，指纹每次运行使用随机盐生成，不保证跨运行稳定。

## 退出码

- `0`：命令成功执行。`scan` 即使发现敏感信息，默认也返回 `0`。
- `1`：`scan --fail-on-findings` 发现敏感信息，或管道输出中断。
- `2`：文件读取、写入或其他本地 I/O 错误。

## Python API

### 识别字段名

```python
from secret_guard import classify_key_name, is_sensitive_key

assert is_sensitive_key("deepseek_api_key")
assert is_sensitive_key("xxxxxxapikey")
assert classify_key_name("clientSecret").value == "secret"
```

配置额外敏感字段或忽略字段：

```python
from secret_guard import is_sensitive_key

is_sensitive_key("model_cookie", extra_sensitive_keys={"model_cookie"})
is_sensitive_key("max_tokens", ignored_keys={"max_tokens"})
```

### 解析赋值语法

```python
from secret_guard import parse_assignment

assignment = parse_assignment("api_key=replace-with-real-value")

if assignment is not None:
    print(assignment.key)
    print(assignment.value)
```

### 判断高置信密钥值

```python
from secret_guard import is_high_confidence_secret_value

is_high_confidence_secret_value("sk-12345678901234567890")
```

### 识别公网 IP 和端口

```python
from secret_guard import is_interesting_public_ip, is_unusual_public_endpoint

is_interesting_public_ip("93.184.216.34")
is_unusual_public_endpoint("93.184.216.34:45678")
```

### 扫描文本

```python
from secret_guard import scan_text

findings = scan_text(
    "api_key=replace-with-real-value",
    path=".env",
)

for finding in findings:
    print(finding.category, finding.path, finding.line, finding.key, finding.fingerprint)
```

### 扫描文件和目录

```python
from secret_guard import scan_file, scan_path

file_findings = scan_file("backend/.env")
repo_findings = scan_path(".")
```

排除路径：

```python
from secret_guard import scan_path

findings = scan_path(".", excluded_paths={".venv", "node_modules"})
```

限制完整文本扫描大小：

```python
from secret_guard import scan_path

findings = scan_path(".", max_text_bytes=1024 * 1024)
```

### 扫描 SQLite

```python
from secret_guard import scan_sqlite

findings = scan_sqlite("config.db")
```

SQLite 扫描会查找包含 `key` 和 `value` 字段的表。

### 扫描 Git 历史

```python
from secret_guard import scan_git_history

findings = scan_git_history(".")
```

Git 历史扫描会检查当前仓库可达提交中的高风险内容。

### 脱敏文本和值

```python
from secret_guard import redact_text, redact_value

safe_text = redact_text("password=replace-with-real-value")
safe_value = redact_value("api_key", "replace-with-real-value")
```

自定义占位符和输出长度：

```python
from secret_guard import redact_value

safe_value = redact_value(
    "api_key",
    "replace-with-real-value",
    replacement="[hidden]",
    max_length=40,
)
```

### 结构化脱敏结果

```python
from secret_guard import redact_result

result = redact_result("api_key", "replace-with-real-value")

print(result.as_text())
print(result.as_dict())
print(result.as_json())
```

`redact_result` 会返回统一对象，并在发生脱敏时附带不可逆指纹。

### 生成改写计划

```python
from secret_guard import build_rewrite_plan

plan = build_rewrite_plan("backend/.env")

if plan.has_changes():
    print(plan.diff())
```

改写计划不会修改文件。`diff()` 不会输出原始敏感值。

### 执行改写

```python
from secret_guard import apply_rewrite_plan, build_rewrite_plan

plan = build_rewrite_plan("backend/.env")
result = apply_rewrite_plan(plan, in_place=True, backup=True)

print(result.changed)
print(result.backup_path)
```

只有显式传入 `in_place=True` 时才会写入文件。`backup=True` 会在写入前生成 `.bak` 文件。

### 移除敏感值

```python
from secret_guard import build_rewrite_plan

plan = build_rewrite_plan("backend/.env", remove=True)
```

### 自定义替换值

```python
from secret_guard import build_rewrite_plan

plan = build_rewrite_plan("backend/.env", replacement="[redacted]")
```

## 安全边界和限制

`secret-guard` 使用启发式规则，因此：

- 可能存在误报。
- 可能存在漏报。
- 它适合作为开发辅助和仓库卫生检查工具，不应作为唯一安全防线。
- 它不会代替专业密钥扫描、安全审计、合规检查或安全事件响应工具。
- 报告、日志、diff 预览和异常信息都不应该输出原始敏感值。
- 改写功能默认 dry-run，必须显式传入 `--apply` 或 `in_place=True` 才会修改文件。

如果发现敏感信息已经进入 Git 历史，通常需要立即轮换对应密钥；如仓库已经上传到远端，还需要评估是否重写历史并通知协作者。
