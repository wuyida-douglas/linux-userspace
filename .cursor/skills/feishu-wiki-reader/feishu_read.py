#!/usr/bin/env python3
"""
飞书文档读取工具：绕过 Cursor MCP 封装层，直接调用飞书 MCP 协议。

用法:
  python3 feishu_read.py wiki <wiki_token>      # wiki 节点 → docx ID
  python3 feishu_read.py docx <docx_token>      # 读文档内容
  python3 feishu_read.py comments <docx_token>  # 读文档评论

可通过 --url 或 FEISHU_MCP_URL 提供 MCP 地址，否则读取 mcp.json。
"""

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path


def load_mcp_url(explicit_url=None):
    """从显式参数、环境或 mcp.json 加载飞书 MCP URL。"""
    if explicit_url:
        return explicit_url
    if os.environ.get("FEISHU_MCP_URL"):
        return os.environ["FEISHU_MCP_URL"]
    candidates = [
        Path("/nvme/wuyida/mcp.json"),
        Path.home() / ".cursor/mcp.json",
        Path(__file__).resolve().parents[3] / ".cursor/mcp.json",
        Path("/mnt/shared-storage-user/datafactory-share/wuyida/.cursor/mcp.json"),
    ]
    for mcp_path in candidates:
        if not mcp_path.is_file():
            continue
        with mcp_path.open(encoding="utf-8") as file:
            cfg = json.load(file)
        try:
            return cfg["mcpServers"]["feishu-mcp"]["url"]
        except KeyError as error:
            raise ValueError(f"{mcp_path} 缺少 mcpServers.feishu-mcp.url") from error
    searched = "、".join(str(path) for path in candidates)
    raise FileNotFoundError(
        "未找到飞书 MCP URL。请配置 ~/.cursor/mcp.json 的 "
        f"mcpServers.feishu-mcp.url，或设置 FEISHU_MCP_URL。已检查：{searched}"
    )


def mcp_call(url, method, params=None, msg_id=1):
    """发送 MCP 协议请求，兼容 JSON 和 SSE 响应。"""
    payload = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        body = response.read().decode()
    # SSE format: lines starting with "data:". Return the matching response,
    # not an event that happens to precede it.
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            return None
        try:
            message = json.loads(data)
        except json.JSONDecodeError:
            continue
        if message.get("id") == msg_id:
            return message
    message = json.loads(body)
    if "error" in message:
        raise RuntimeError(message["error"])
    return message


def tool(url, name, args, msg_id=1):
    """调用 MCP 工具，检查协议错误。"""
    mcp_call(url, "initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "feishu-reader", "version": "1.0"},
    }, msg_id=0)
    response = mcp_call(url, "tools/call", {"name": name, "arguments": args}, msg_id=msg_id)
    if not response or "error" in response:
        raise RuntimeError(response.get("error") if response else "MCP 未返回响应")
    return response


def result_text(response):
    return response["result"]["content"][0]["text"]


def wiki_to_docx(url, wiki_token):
    """wiki 节点 → docx token。"""
    response = tool(url, "wiki_v2_space_getNode", {"query": {"token": wiki_token}})
    data = json.loads(result_text(response))
    node = data["data"]["node"]
    return node["obj_token"], node.get("title", "")


def read_docx(url, docx_token):
    """读文档纯文本内容。"""
    response = tool(url, "docx_v1_document_rawContent", {
        "path": {"document_id": docx_token},
        "query": {"lang": 0},
    })
    data = json.loads(result_text(response))
    return data["data"]["content"]


def read_comments(url, docx_token):
    """读文档评论。"""
    response = tool(url, "drive_v1_fileComment_list", {
        "path": {"file_token": docx_token},
        "query": {"file_type": "docx"},
    })
    return json.loads(result_text(response))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["wiki", "docx", "comments"])
    parser.add_argument("token")
    parser.add_argument("--url", help="飞书 MCP URL；建议改用 FEISHU_MCP_URL 避免进入终端历史")
    args = parser.parse_args()
    url = load_mcp_url(args.url)

    if args.command == "wiki":
        docx_token, title = wiki_to_docx(url, args.token)
        print(f"docx_token={docx_token}")
        print(f"title={title}")
        print(f"\n读内容请执行: python3 {sys.argv[0]} docx {docx_token}")
    elif args.command == "docx":
        print(read_docx(url, args.token))
    else:
        data = read_comments(url, args.token)
        comments = data.get("data", {}).get("items", [])
        for comment in comments:
            print(f"[{comment.get('create_time', '')}] {comment.get('content', '')}")
            print("---")


if __name__ == "__main__":
    main()
