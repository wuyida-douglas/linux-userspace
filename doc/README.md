# 文档索引与状态

> 最后核对：2026-11-10。
> 当前实现以代码和根目录 `README.md` 为准；本页标明每份文档是否仍是当前口径。

## 当前权威

| 文档 | 内容 |
|---|---|
| [`../README.md`](../README.md) | 运行入口、数据准备、批次、输出位置、严格验收 |
| [`Harbor验收设计.md`](Harbor验收设计.md) | 当前两次 Harbor Agent 跑题 + Pass2Fail 验收 |
| [`main与runner镜像说明.md`](main与runner镜像说明.md) | main/client/runner 镜像与容器边界 |
| [`healthcheck执行位置与责任.md`](healthcheck执行位置与责任.md) | healthcheck 在哪个容器、以什么身份、何时执行 |
| [`交付合同与健康检查设计.md`](交付合同与健康检查设计.md) | Compose、生成的 `task.json`、healthcheck |
| [`pipeline-prompts.md`](pipeline-prompts.md) | 当前 Prompt 原文索引 |
| [`Pipeline Prompts（完整版）中文翻译.md`](Pipeline%20Prompts（完整版）中文翻译.md) | 按分支展开的中文 Prompt 全文 |
| [`审查阶段可见内容与边界.md`](审查阶段可见内容与边界.md) | Review 可见内容、`live.chat.md`、只读边界 |
| [`可写Bind恢复说明.md`](可写Bind恢复说明.md) | `pristine-binds.tar`、wrapper、预跑/收尾恢复与边界 |
| [`输入下载与预处理.md`](输入下载与预处理.md) | 候选池、S3 下载、manifest、固定样本 |

## 分支详解

- [`SVC-EXPLOIT分支全流程详解.md`](SVC-EXPLOIT分支全流程详解.md)
- [`FILE-EXPLOIT分支全流程详解.md`](FILE-EXPLOIT分支全流程详解.md)
- [`FILE-POV分支全流程详解.md`](FILE-POV分支全流程详解.md)

这三份是 2026-11-09 的全流程长文，仍可作为字段和流程参考，但顶部已标注：

- 验收已改为两次 Harbor Agent 跑题 + Pass2Fail；
- `task.json` 已改为控制器生成，agent 不再手写；
- 文中“写 task.json / 改 task.json.images”的段落属于旧流程。

## 历史/设计背景

| 文档 | 状态 |
|---|---|
| [`Linux用户态漏洞利用新管线计划.md`](Linux用户态漏洞利用新管线计划.md) | 2026-11-03 历史计划，仅保留设计背景 |
| `统一Harbor交付与差分验证设计.md` | 已移除；当前交付/验收看 `Harbor验收设计.md` |

## 已删除/合并的旧概念

- `pipeline.iterate_batches` / `iterate.py` 协调器已移除；批次由 Agent 直接启动
  `pipeline.supervise`。
- `conversation.md` 已删除；审查看 `review-input/live.chat.md`，
  SFT 用 `sft.jsonl`（Qwen/OpenAI 风格 messages + tool_calls/tool role），`trajectory.jsonl` 只保留 turn 索引。
- `task.json` 仍存在，但由 `pipeline.contract_build.build_task_contract()` 生成；
  agent 只写 Compose 和固定脚本。