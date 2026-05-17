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

## 开发计划

开发顺序和完成清单见 [docs/development-plan.md](docs/development-plan.md)。

## 安装

从本地仓库安装：

```bash
pip install -e .
```

从 GitHub 安装：

```bash
pip install git+https://github.com/xiaohan2004/secret-guard.git
```

安装固定 tag：

```bash
pip install git+https://github.com/xiaohan2004/secret-guard.git@v0.1.0
```

## Agent Skill

仓库内提供了一个 `scan-secrets` skill：

```text
skills/scan-secrets
```

### 手动安装

复制到本地 agent skills 目录，例如 Codex：

```powershell
Copy-Item -Recurse -Force .\skills\scan-secrets "$env:USERPROFILE\.codex\skills\"
```

如果使用其他 coding agent，请复制到对应工具的 skills 目录。

### 自然语言安装

也可以让正在使用的 coding agent 帮你安装，例如：

```text
请从 https://github.com/xiaohan2004/secret-guard/tree/master/skills/scan-secrets 安装 scan-secrets skill 到我的本地 skills 目录。
```

## 使用说明

完整使用说明见 [docs/usage.md](docs/usage.md)。

最常用的仓库审计命令：

```bash
secret-guard audit .
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

## 许可证

MIT
