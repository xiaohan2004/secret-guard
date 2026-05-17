# secret-guard

`secret-guard` 是一个轻量级 Python 工具库，用于识别、扫描、脱敏和改写本地项目中暴露的机密信息与敏感基础设施信息。

这个项目主要服务于我自己的工具链。项目公开发布只是为了方便安装和复用，但在 `0.x` 版本期间 API 可能会随个人需求调整。


## 目标范围

`secret-guard` 主要关注这些类型的信息：

- API key
- access key
- token
- password
- credential
- private key
- authorization 值
- 账号类字段，例如 username、account、email
- 公网 IP
- 公网 IP 加非常见端口

它适合用于本地检查、开发辅助工具、仓库卫生检查。它不是专业密钥扫描工具、安全审计工具、合规审查工具或安全事件响应工具的替代品。

## 开发顺序

1. 识别

   识别是所有后续功能的基础。扫描、脱敏、改写都必须依赖统一的识别规则。

   - [x] 判断字段名是否像敏感字段，例如 `apiKey`、`access-token`、`clientSecret`
   - [x] 支持大小写、连接符、下划线、点号等命名差异
   - [x] 支持项目侧传入额外敏感字段集合
   - [x] 识别常见赋值语法，例如 `key=value`、`key: value`、带引号的配置值
   - [x] 识别高置信密钥值，例如常见 API key、云厂商 key、GitHub token、私钥头
   - [x] 区分密钥类、账号类、网络地址类等敏感类别
   - [x] 识别公网 IP
   - [x] 识别公网 IP 加非常见端口
   - [x] 区分常见公共 IP 与需要关注的公网 IP
   - [x] 过滤明显占位值，例如 `your-api-key`、`example`、`test-key`
   - [x] 避免把 `max_tokens`、`tokens_count` 这类计数字段误判为 token
   - [x] 支持调用方配置额外规则、忽略规则和常见端口列表
   - [x] 为识别规则补完整测试用例

2. 扫描

   扫描负责把识别能力应用到具体输入源上。扫描结果不能暴露原始敏感值。

   - [x] 扫描纯文本
   - [x] 扫描单个文件
   - [x] 扫描目录
   - [x] 区分配置文件、代码文件、数据库文件和普通文本文件
   - [x] 跳过常见依赖目录和缓存目录
   - [x] 跳过或限制大型文件、二进制文件
   - [x] 对二进制或大文件只做高置信模式扫描，避免完整解析
   - [x] 扫描 SQLite key/value 表
   - [x] 扫描 Git 历史
   - [x] 支持只扫描工作区、不扫描 Git 历史
   - [x] 支持传入扫描根目录和排除路径
   - [x] 输出结构化发现结果，包括路径、行号、类别、不可逆指纹
   - [x] 合并重复发现，避免同一位置重复报告

3. 脱敏

   脱敏负责把扫描结果或任意值安全展示出来。它依赖识别结果，不应该绕过识别规则自己判断一套逻辑。

   - [x] 根据字段名隐藏敏感值
   - [x] 对文本里的 `token=...`、`password:...` 等片段做内联脱敏
   - [x] 对 URL 中的用户名密码片段做脱敏
   - [x] 支持最大输出长度，避免长提示词或长配置刷屏
   - [x] 支持把多行值压缩为单行预览，避免提示词或证书内容刷屏
   - [x] 支持自定义脱敏占位符，例如 `[secret hidden]`
   - [x] 支持统一的输出对象格式
   - [x] 支持文本、JSON 等输出格式
   - [x] 支持稳定但不可逆的敏感值指纹
   - [x] 确保扫描报告、日志和异常信息都不输出原始敏感值

4. 改写

   改写是最高风险功能，必须建立在扫描结果和脱敏稳定之后。

   - [x] 根据扫描结果生成改写计划
   - [x] 默认 dry-run，只展示将修改什么
   - [x] 显式确认后才允许原地修改
   - [x] 支持写入备份文件
   - [x] 支持把敏感值替换为占位符
   - [x] 支持移除敏感值
   - [x] 支持只改写明确命中的文本范围，避免整文件格式被重写
   - [x] 支持改写前后 diff 预览
   - [x] 防止误改二进制文件、依赖目录、Git 内部目录
   - [x] 改写失败时保留原文件，避免部分写入造成文件损坏

## 安装

从本地仓库安装：

```bash
pip install -e .
```

从 GitHub 安装：

```bash
pip install git+https://github.com/your-name/secret-guard.git
```

安装固定 tag：

```bash
pip install git+https://github.com/your-name/secret-guard.git@v0.1.0
```

## 使用说明

### 命令行审计

`audit` 是给日常仓库检查和 Codex skill 使用的固定格式报告：

```bash
secret-guard audit .
```

它会输出两部分：

- `1、是否存在敏感信息`
- `2、敏感信息是否进入git提交`

报告只展示文件路径、位置、类别和不可逆标识，不展示原始敏感值。

### 命令行扫描

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

### 命令行脱敏

```bash
secret-guard redact "api_key=replace-with-real-value"
```

默认会把敏感值替换为 `[secret hidden]`。也可以指定占位符：

```bash
secret-guard redact "password=replace-with-real-value" --replacement "[hidden]"
```

### 命令行改写

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

### Python API

```python
from secret_guard import scan_path, redact_text, build_rewrite_plan

findings = scan_path(".")
safe_text = redact_text("api_key=replace-with-real-value")
plan = build_rewrite_plan("backend/.env")

if plan.has_changes():
    print(plan.diff())
```

## 命名约定

- 仓库名：`secret-guard`
- Python 包名：`secret-guard`
- Python 导入名：`secret_guard`
- CLI 命令：`secret-guard`

## 安全边界

`secret-guard` 使用启发式规则。这意味着：

- 可能存在误报
- 可能存在漏报
- 它应该作为额外安全层，而不是唯一保护手段
- 报告和日志里不应该直接输出敏感原值
- 改写功能必须默认 dry-run，不能默认进行破坏性修改

## 开发

运行测试：

```bash
python -m pytest
```

用 Python 编译器做语法检查：

```bash
python -m py_compile src/secret_guard/*.py
```

## 许可证

MIT
