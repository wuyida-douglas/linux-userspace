# Linux 用户态漏洞题目管线

把固定 CVE/OSV 候选池变成可跑的 Harbor 题包。只保留三条主流程：

```text
准备数据 → 选定题目并启动合成 → 选定题目并启动评测
```

细节分别在 `doc/`，日常操作只看本页。

## 0. 前置条件

- Python 虚拟环境：`.venv/`
- Docker + Docker Compose
- Harbor **0.22.0**，且在 `PATH` 中
- 模型环境文件（默认 `/nvme/wuyida/env`）：

```text
ANTHROPIC_BASE_URL=...
ANTHROPIC_API_KEY=...        # 或 ANTHROPIC_AUTH_TOKEN
```

- 本机 `claude` 可执行文件（评测时挂进 main）

> 当前是共享宿主 Docker 的开发模型，不是最终多租户隔离。不要把凭据写进
> Compose、镜像或题包；`results/`、`harbor_export/`、`logs/` 都是本地产物，
> 默认不提交。

## 1. 一键准备数据

固定随机样本：

```bash
cd /nvme/wuyida/新管线开发
scripts/prepare_sample.sh samples/my100 100 20261120 4
# 参数：<输出目录> [数量=100] [seed=当天] [workers=4]
```

全量冻结池：

```bash
scripts/prepare_full_pool.sh samples/full-20261109 30
# 参数：<输出目录> [workers=30]
```

输出：

```text
samples/<name>/
├── selection.jsonl          # 选中的 task id、候选和恢复线索
├── sample.json
├── download-report.json
└── tasks/<task-id>/input/   # src/、fix.diff、meta.json、manifest.json
```

准备只下载和校验输入，不调用模型、不路由。

## 2. 选定数据，一键启动合成

从 `selection.jsonl` 里选 task id，交给 supervisor：

```bash
scripts/synthesize.sh \
  samples/my100 \
  results/my-batch-01 \
  /nvme/wuyida/env \
  <task-id-1> <task-id-2> ...
```

参数：

```text
<sample-dir> <results-dir> <env-file> <task-id...>
```

可调环境变量：

```bash
CONCURRENCY=4 scripts/synthesize.sh ...
```

流程固定为：路由 → 合成 → 独立 review → 两次 Harbor Agent 验收。
只有 review 通过且两次 reward 都是 1.0 的题才会发布到
`harbor_export/<日期>-production/`。

结果：

```text
results/<run>/<internal-task-id>/
├── workspace/
├── route/ synthesis/ review/
├── harbor/
└── result.json
```

批次结束后会写 `display-names.json`，记录内部目录到
`cve-...-file-pov` / `...-svc-exploit-...` 的展示名；结果目录本身不改名。

## 3. 选定数据，一键启动评测

对已经发布的 bundle 跑单题（可多个）：

```bash
scripts/evaluate.sh \
  harbor_export/20261111-production \
  cve-2024-23346-file-pov \
  cve-2020-28483-svc-exploit-synthetic-host
```

参数：

```text
<bundle-dir> <task-id...>
```

脚本会：

- 用 `bin/load_image.py --task` 加载镜像并恢复可写 bind；
- 用 `load_image.py --run` 包住 `harbor run`，前后各恢复一次；
- 自动设置 `PYTHONPATH`；
- 只挂本机 `claude`，不挂参考 PoC；
- 结果写到 `eval-jobs/<job-name>/`。

可调环境变量：

```bash
MODEL=glm-5.3 MAX_TURNS=300 \
CLAUDE_BIN=/path/to/claude \
ANTHROPIC_API_KEY=... ANTHROPIC_BASE_URL=... \
scripts/evaluate.sh <bundle> <task-id>
```

评测结果看：

```text
eval-jobs/<job-name>/.../result.json
  verifier_result.rewards.reward
```

`1.0` 通过，`0.0` 未通过；没有 reward 是判分没完成（基础设施/题目缺陷），
不是 agent 的 0 分。

## 4. 目录与清理

```text
pipeline/       # 管线代码
scripts/        # 三个一键入口 + 数据/审计工具
samples/        # 样本选择与输入（大文件在 S3 / 本地）
results/        # 运行结果（gitignore）
harbor_export/  # 已发布题包（gitignore）
logs/           # 运行日志（gitignore）
doc/            # 设计、验收、分支说明、审计报告
```

历史批次和旧导出已经移到 `/nvme/wuyida/trashcan/`；需要回看时去那里找，
不要重新放回管线根目录。

## 5. 详细文档

- [Harbor 验收设计](doc/Harbor验收设计.md)
- [可写 Bind 恢复说明](doc/可写Bind恢复说明.md)
- [审查阶段可见内容与边界](doc/审查阶段可见内容与边界.md)
- [Pipeline Prompts（完整版）](doc/pipeline-prompts.md)
- [SVC-EXPLOIT](doc/SVC-EXPLOIT分支全流程详解.md) /
  [FILE-EXPLOIT](doc/FILE-EXPLOIT分支全流程详解.md) /
  [FILE-POV](doc/FILE-POV分支全流程详解.md)
- [审计报告 2026-11-11](doc/iteration-reports/audit-20261111-task-quality.md)
- [文档索引](doc/README.md)