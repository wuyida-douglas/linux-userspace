---
name: feishu-wiki-reader
description: 读取飞书知识库(wiki)链接的文档内容。当用户发送 https://aicarrier.feishu.cn/wiki/xxx 形式的链接，或 Cursor 的 CallDynamicTool 调用 wiki_v2_space_getNode 报 "token is required" 时使用。也用于读取 docx 文档和获取文档评论。
---

# 飞书知识库文档读取

## 问题根源

飞书 MCP 服务提供 `wiki_v2_space_getNode` 工具，用于把 wiki 链接（`https://aicarrier.feishu.cn/wiki/<node_token>`）解析为实际文档 ID（`docx_token`）。

但 **Cursor 的 `CallDynamicTool` 封装层有 bug**：它把参数 `{"query": {"token": "..."}}` 转换错误，导致飞书服务端报 `token is required`。这不是授权问题，也不是飞书 API 限制。

## 解决方案：直接调 MCP 协议

绕过 Cursor 的封装，用 Python 直接发送 MCP 协议请求。

### 快速用法

在本仓库根目录运行：

```bash
python3 .cursor/skills/feishu-wiki-reader/feishu_read.py wiki <wiki_token>
python3 .cursor/skills/feishu-wiki-reader/feishu_read.py docx <docx_token>
python3 .cursor/skills/feishu-wiki-reader/feishu_read.py comments <docx_token>
```

### 示例

```bash
# 读 wiki 节点 → 获取背后的 docx ID
python3 .cursor/skills/feishu-wiki-reader/feishu_read.py wiki RCNXwrJeZinoBhkhAjkcOW2jnDh
# 输出: docx_token=NrH9dOlzToUWsdxPmJ8cgUChnvb title=自建代理仓库

# 读文档内容
python3 .cursor/skills/feishu-wiki-reader/feishu_read.py docx NrH9dOlzToUWsdxPmJ8cgUChnvb

# 读文档评论
python3 .cursor/skills/feishu-wiki-reader/feishu_read.py comments NrH9dOlzToUWsdxPmJ8cgUChnvb
```

### 从 URL 提取 token

- wiki 链接：`https://aicarrier.feishu.cn/wiki/RCNXwrJeZinoBhkhAjkcOW2jnDh` → token = `RCNXwrJeZinoBhkhAjkcOW2jnDh`
- docx 链接：`https://aicarrier.feishu.cn/docx/TfrIdSStEoX48CxgnWHc8ZqXnoV` → token = `TfrIdSStEoX48CxgnWHc8ZqXnoV`

## 脚本位置

`feishu_read.py` 就在本 skill 目录下，直接执行即可。不需要安装额外依赖（只用标准库）。

## 注意事项

- MCP 服务 URL 从 `FEISHU_MCP_URL`、本机 `/nvme/wuyida/mcp.json`、用户级 `~/.cursor/mcp.json`、项目级 `.cursor/mcp.json` 或原始共享路径 `/mnt/shared-storage-user/datafactory-share/wuyida/.cursor/mcp.json` 读取。
- 配置文件格式为 `{"mcpServers": {"feishu-mcp": {"url": "..."}}}`。也可用 `--url` 显式传入，避免在终端历史中留下 URL。
- 该 URL 有效期 7 天，过期后需用户在飞书 MCP 后台重新生成并更新 mcp.json。
- 如果报 `invalid token` 或 `access denied`，说明文档未分享给当前用户，或链接已失效。
- 不要把包含凭据的 MCP URL 写入技能文件、日志或提交。
