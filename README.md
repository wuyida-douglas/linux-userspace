# Linux 用户态漏洞题目管线

## 0. 前置条件

- Python 虚拟环境：`/nvme/wuyida/新管线开发/.venv/`
- Docker + Docker Compose
- Harbor **0.22.0**，且在 `PATH` 中
- 模型环境文件：`/nvme/wuyida/env`

```text
ANTHROPIC_BASE_URL=...
ANTHROPIC_API_KEY=...        # 或 ANTHROPIC_AUTH_TOKEN
```

> 当前是共享宿主 Docker 的开发模型，不是最终多租户隔离。不要把凭据写进
> Compose、镜像或题包；`results/`、`harbor_export/`、`logs/` 都是本地产物，
> 默认不提交。

## 1. 一键准备数据

### 1.1 按批次准备

脚本：`/nvme/wuyida/新管线开发/scripts/prepare_batch.sh`

```sh
# ===== 直接改这里 =====
BATCH=1
OUTPUT=/nvme/wuyida/新管线开发/samples/batch-01
WORKERS=30
# ======================
```

运行：

```bash
/nvme/wuyida/新管线开发/scripts/prepare_batch.sh
```

- `BATCH`：冻结池里的批次号，1..12。
- `OUTPUT`：样本目录。
- `WORKERS`：下载并发，1..30。

冻结候选池：

```text
/nvme/wuyida/新管线开发/data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl
```

每行带 `batch` 键。batch 1–11 各 2,000 条，batch 12 为 138 条；不同 batch 的
`instance_id` 互不重复。同一 batch 重复执行会复用已有缓存并校验清单，不会重新
抽题或重复下载。

准备过程会显示完成数、失败数、耗时和 ETA；按 `Ctrl-C` 后重新运行同一脚本即可
续跑。下载完成后不要删除 `tasks/<task-id>/`，否则该题会被视为输入不可用。

### 1.2 输出

```text
/nvme/wuyida/新管线开发/samples/<name>/
├── selection.jsonl          # 选中的 task id、候选和恢复线索（含 batch）
├── sample.json              # batch 模式额外记录 batch、batch_total、batch_rows
├── download-report.json
└── tasks/<task-id>/input/   # src/、fix.diff、meta.json、manifest.json
```

准备只下载和校验输入，不调用模型、不路由。

## 2. 一键启动合成

脚本：`/nvme/wuyida/新管线开发/scripts/synthesize.sh`

```sh
# ===== 直接改这里 =====
SAMPLE=/nvme/wuyida/新管线开发/samples/batch-01
RESULTS=/nvme/wuyida/新管线开发/results/batch-01
ENV_FILE=/nvme/wuyida/env
MODE=tasks-file
TASKS_FILE=/nvme/wuyida/新管线开发/samples/batch-01/todo.txt
CONCURRENCY=40
WAVE_SIZE=0
DRY_RUN=0
EXPECT_BATCH=1
# ======================
```

运行：

```bash
/nvme/wuyida/新管线开发/scripts/synthesize.sh
```

配置项：

```text
MODE=all           合成 selection.jsonl 的全部题目（当前批次 2000 条）
MODE=tasks-file    只合成 TASKS_FILE 里列出的题目
TASKS_FILE         任务清单；只在 tasks-file 模式使用
CONCURRENCY        同时运行的 worker 数，1..40，默认 40
WAVE_SIZE          0 = 所有题交给一个 supervisor 连续调度（默认，无 wave 屏障）；
                   正数 = 旧的有界 wave 模式，每 N 题重启一次 supervisor
DRY_RUN=1          只打印目标和 batch 划分，不启动模型
EXPECT_BATCH       校验 sample.json 里的 batch 号；留空表示不校验
```

`TASKS_FILE` 支持：

- 纯文本，一行一个 id，`#` 开头为注释；
- JSONL，每行一个对象，取 `task_id` 或 `instance_id`；
- JSON 数组，元素为字符串或带 `task_id`/`instance_id` 的对象。

id 可以是内部 `task_id`、`instance_id`、样本内唯一的 `canonical_id`，或
`display-names.json` 里的展示名。未知/歧义 id 会在任何模型调用之前报错。

`CONCURRENCY` 和 `WAVE_SIZE` 的区别：

- **默认 `WAVE_SIZE=0`**：协调器把所有目标题一次性交给一个 supervisor。
  supervisor 按 `CONCURRENCY` 连续调度：某个题结束、空出 slot，就立即从
  候选队列里补下一题，**没有 wave 屏障，不会被最慢的题拖住后续批次**。
- `CONCURRENCY`：同时运行的 worker 数，1..40。这是真正的并发度。
- `WAVE_SIZE>0` 是保留的旧模式：每 N 题调用一次 supervisor，当前 wave 的题
  都进入终态后才启动下一个 wave。只有在你刻意想限制单个 supervisor 的
  状态/重启粒度时才需要；50 题、`WAVE_SIZE=40` 会变成 40+10 两个 wave。
- 正常情况下保持 `WAVE_SIZE=0` 即可；2000 题也会作为一个连续池调度。
- supervisor 单次最多接受 100000 个 fresh id，所以 2000 题不需要拆分。

旧版的 `CONCURRENCY` 环境变量已不再使用，直接改脚本里的配置。

### 2.1 断点续跑与失败重跑

- **中断后继续**：原样再运行一次脚本。已 `passed` / `rejected` 的题会跳过，
`routing` / `synthesizing` / `reviewing` / `harbor` 中断的题会从保留的
route / synthesis 状态继续，不会重新抽题。
- `Ctrl-C` 会停掉协调器和当前 supervisor；已经启动的 `pipeline.run` worker
在独立 session 里，可能继续把当前题跑完。重跑时新 supervisor 会接管这些
worker，不会重复启动。
- **失败即终态（强制）**：`failed` / `error` 的题不会被重新加入队列，
`--retry-failed` 已禁用，也没有任何自动 requeue 脚本。需要重做某一道题时，
只能人工对该题单独起一次运行；不要写进批次循环。
只有 `routing` / `synthesizing` / `reviewing` / `harbor` 这类中断状态会从保留的
workspace 继续。
- 输入缺失（`input_unavailable` 或没有 `tasks/<task>/input/manifest.json`）的题
不会被自动重跑；先把输入补齐。
- 也可以从汇总里导出失败题，写进 `TASKS_FILE` 后按 `MODE=tasks-file` 精确重跑：

```bash
jq -r '.failures[].task_id' \
  /nvme/wuyida/新管线开发/results/batch-01/synthesis-summary.json \
  > /nvme/wuyida/新管线开发/samples/batch-01/todo.txt
```

### 2.2 后台运行（nohup）

先改好 `synthesize.sh` 顶部的配置，然后：

```bash
mkdir -p /nvme/wuyida/新管线开发/results/batch-01/logs
nohup /nvme/wuyida/新管线开发/scripts/synthesize.sh \
  > /nvme/wuyida/新管线开发/results/batch-01/logs/nohup-synthesize.log 2>&1 &
echo $! > /nvme/wuyida/新管线开发/results/batch-01/synthesize.pid
```

查看日志：

```bash
tail -f /nvme/wuyida/新管线开发/results/batch-01/logs/nohup-synthesize.log
```

### 2.3 停止

脚本：`/nvme/wuyida/新管线开发/scripts/stop_synthesis.sh`

```sh
# ===== 直接改这里 =====
RESULTS=/nvme/wuyida/新管线开发/results/batch-01
STOP_WORKERS=0
# ======================
```

运行：

```bash
/nvme/wuyida/新管线开发/scripts/stop_synthesis.sh
```

- `STOP_WORKERS=0`：只停协调器和 supervisor，让已经启动的 `pipeline.run`
worker 把当前题跑完；之后重跑同一脚本会接管它们。
- `STOP_WORKERS=1`：连 `pipeline.run` worker 一起停，做硬停止。

等价的底层命令：

```bash
# 软停止：停协调器和 supervisor
pkill -f 'pipeline[.]synthesize_batch .*--results /nvme/wuyida/新管线开发/results/batch-01'
pkill -f 'pipeline[.]supervise .*--results /nvme/wuyida/新管线开发/results/batch-01'

# 硬停止：再停掉 worker
pkill -f 'pipeline[.]run .*--results /nvme/wuyida/新管线开发/results/batch-01'
```

## 3. 查看合成进度

脚本：`/nvme/wuyida/新管线开发/scripts/synthesis_status.sh`

```sh
# ===== 直接改这里 =====
SAMPLE=/nvme/wuyida/新管线开发/samples/batch-01
RESULTS=/nvme/wuyida/新管线开发/results/batch-01
TASKS_FILE=/nvme/wuyida/新管线开发/samples/batch-01/todo.txt
# TASKS_FILE=   # 留空 = 统计整个 selection.jsonl
# ======================
```

运行：

```bash
/nvme/wuyida/新管线开发/scripts/synthesis_status.sh
```

示例输出：

```text
synthesis status @ 2026-11-11T09:00:48Z
coordinator: running pid=123456
supervisor:  running pid=123457
workers:     36 process(es) for 36 target task(s)

stage           tasks   live  stale
preparing           0      0      0
routing             2      2      0
synthesizing       30     30      0
reviewing           3      3      0
harbor              1      1      0
passed              3      0      0
rejected            4      0      0
missing             7      0      0

target=50 terminal=7 remaining=43 live_tasks=36 stale=0
```

- `tasks`：目标题中 `result.json` 处于该阶段的题数。
- `live`：该阶段中有真实 `pipeline.run` 进程在跑的题数。
- `stale`：状态是 `preparing` / `routing` / `synthesizing` / `reviewing` /
`harbor`，但没有存活 worker 的题，通常是协调器刚被停掉、等待下次接管。
- 如果协调器/supervisor 已经停了但 worker 还活着，脚本会额外提示。

## 4. 详细文档

- [单题评测 / 跑题](EVAL.md)
- [Harbor 验收设计](doc/Harbor验收设计.md)
- [可写 Bind 恢复说明](doc/可写Bind恢复说明.md)
- [审查阶段可见内容与边界](doc/审查阶段可见内容与边界.md)
- [Pipeline Prompts（完整版）](doc/pipeline-prompts.md)
- [SVC-EXPLOIT](doc/SVC-EXPLOIT分支全流程详解.md) /
[FILE-EXPLOIT](doc/FILE-EXPLOIT分支全流程详解.md) /
[FILE-POV](doc/FILE-POV分支全流程详解.md)
- [审计报告 2026-11-11](doc/iteration-reports/audit-20261111-task-quality.md)
- [文档索引](doc/README.md)
