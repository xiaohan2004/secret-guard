---
name: scan-secrets
description: Scan a repository with secret-guard audit for leaked credentials and sensitive information such as API keys, passwords, tokens, client secrets, private keys, .env values, SQLite-stored keys, public IPs, and unusual ports, then report workspace findings, Git history findings, and any skipped-file warnings. Use when the user asks to check a repository for leaked credentials, sensitive information, API keys, passwords, tokens, secrets, or committed secrets.
---

# 敏感信息扫描

使用 `secret-guard audit` 完成检查，避免重新组织大量搜索命令：

```powershell
secret-guard audit <repo-path>
```

如果用户没有指定路径，默认对当前仓库运行：

```powershell
secret-guard audit .
```

如果当前环境还没有安装 `secret-guard`，先从 GitHub 安装：

```powershell
pip install git+https://github.com/xiaohan2004/secret-guard.git
```

工具输出固定包含三部分：

1. `1、是否存在敏感信息`
   - 扫描当前工作区，包括未跟踪文件。
   - 命中包括真实密钥格式、配置中的非占位敏感值、SQLite key/value 表中有值的敏感 key、账号字段、公网 IP 和公网 IP 加非常见端口。
   - 列出文件路径、位置、类别和不可逆标识；不展示敏感原值、长度或可复原片段。

2. `2、敏感信息是否进入git提交`
   - 扫描 Git 历史中的高风险内容。
   - 列出已进入提交的文件路径、位置、类别和不可逆标识；不展示敏感原值、长度或可复原片段。

3. `3、是否存在跳过文件`
   - 报告因为极大文件、不可读文件等原因未扫描的文件。
   - 列出文件路径、跳过原因和文件大小；不展示文件内容。

安全要求：

- 大模型只能依据 `secret-guard audit` 输出进行汇报；不要自行打开、复制、复述命中文件中的敏感行。
- 不要把命中文件内容粘贴进对话或发送给外部大模型；如需定位，只使用工具给出的文件、位置、类别和不可逆标识。
- 不可逆标识由工具在本次运行内用随机盐生成短 HMAC 指纹，只用于区分同一次扫描中的命中项；它不展示原值、不展示长度，也不保证跨运行一致。
- 工具只做本地文件系统和本地 Git 历史扫描，不访问网络，不调用外部服务。
- 依赖目录、构建产物、缓存目录和常见二进制文件会被跳过，避免扫描第三方下载内容和无意义大文件。
- 跳过文件不代表安全，只表示工具没有读取或完整扫描这些文件；汇报时要提醒用户按路径人工确认是否需要单独处理。

汇报时保持工具结论，不要复述或暴露具体密钥内容。根据前两项结果给出不同提醒：

- 否、否：说明目前仓库未发现敏感信息。
- 是、否：说明敏感信息只存在于本地工作区，尚未进入 Git 提交；提醒用户把这些文件加入 `.gitignore` 或确认已有忽略规则，不要 `git add -f` 误提交。
- 是、是：说明敏感信息已经进入 Git 历史；提醒用户先确认仓库是否已经上传到 GitHub/Gitee 等网络平台。简要建议处理方式：立即轮换泄露的密钥；从当前代码中移除敏感文件并提交；如确实需要清理历史，使用 `git filter-repo` 或 BFG 重写历史，然后强推并通知协作者重新拉取。
- 否、是：这种情况一般少见，通常表示当前工作区已清理但历史仍有泄露；提醒用户按“是、是”的历史泄露方式处理。

如果第三项为“是”，额外说明存在跳过文件，当前结论不覆盖这些文件内容；建议用户自行检查这些文件是否包含敏感信息，并判断文件是否应加入排除列表、降低文件大小、单独扫描，或确认它们不需要被扫描。
