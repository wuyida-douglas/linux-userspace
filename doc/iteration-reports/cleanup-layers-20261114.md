# 存储与清理全景（2026-11-14）

本文覆盖管线里**所有和存储有关的机制**：磁盘布局、清理分层、阈值及其原因、
哪些操作必须人工、以及 500 题分块跑法。

## 0. 磁盘布局

| 挂载点 | 设备 | 用途 |
|---|---|---|
| `/nvme` | nvme0n1 3.5T | docker 数据（两个 daemon）、`results/`、`samples/`、`harbor_export/`、`TMPDIR` |
| `/` | sda1 864G | 系统与代码；目前约 780G 空闲，可作为静态数据（如 `harbor_export`）的备份盘 |

| 目录 | 内容 |
|---|---|
| `/nvme/docker` + `/nvme/containerd` | daemon A（默认 socket）data-root 与 containerd |
| `/nvme/docker2` + `/nvme/containerd2` | daemon B（`/run/docker2.sock`） |
| `results/` | 每题工作区、日志、评审与验收证据 |
| `samples/` | 题目输入（prepare 从 S3 拉取） |
| `harbor_export/` | 已发布交付包 |
| `/nvme/wuyida/tmp` | 管线 `TMPDIR`（agent 临时文件、pip、claude 会话） |

## 1. 清理分四层

### 1.1 每题终态（立即）

`pipeline/run.py` → `resource_cleanup.cleanup_task`，写 `cleanup.json`：

- 容器：compose working_dir 在题目录下、或 `pipeline.task=<id>`；
- 网络：同上；
- 镜像：`task.json` 声明的 main/client/sidecar（`linux-userspace-*` 受保护）；
- 目录：`harbor/bundle`、`harbor/accept-profile`、`harbor/frozen-delivery`、
  `harbor/jobs/*/verifier/work`、`infrastructure-attempts`、`workspace/.agent-tmp`。

### 1.2 每 30 分钟 housekeeping（批次运行中）

| 动作 | 范围 | 阈值 | 为什么是这个阈值 |
|---|---|---|---|
| `prune_unused_volumes` | 匿名卷 | 立即 | 无引用即安全 |
| `prune_idle_volumes` | results 下的命名卷 | dangling >30min | 活题的网络/卷一定被容器引用 |
| `prune_idle_networks` | results 下的 Compose 网络 | 无容器 >30min | 死网络占子网、拖慢 IPAM |
| `prune_stale_images` | 未被容器引用的镜像 | >12h | **必须大于单题生命周期**：镜像在合成时构建、在 harbor 的 `docker save` 才用到，中间要过完 review（p90 ≈ 83min，长题 2–3h）。设 1.5h 会把在跑题的镜像删掉，验收报 `image is missing` |
| `prune_probe_containers` | agent 探针容器 | >4h 且不在题目录下 | agent 的测试栈可能开几小时；4h 后基本已废弃 |
| `prune_temp_leftovers` | `TMPDIR` 所有条目 | >24h | 里面有活着的 claude 会话目录，过早删会打断在跑 agent |
| `prune_build_cache` | buildkit 缓存 | >6h，且 `/nvme` 空闲 < `MIN_FREE_GB` | 缓存层可能被在跑的题重建复用；prune 持内容存储锁数分钟，不宜频繁 |

### 1.3 分块边界（新增，`run_chunked.sh`）

每 500 题为一个 chunk。chunk 内两个 coordinator 跑完、**所有 worker 退出**后，
对两个 daemon 各执行一次全量清扫（`resource_cleanup --batch-end`）：

- `docker rm -f` **所有容器**；
- 删除**所有未被引用的镜像**（含 agent 探测镜像、基础镜像）；
- `builder prune until=1h`（几乎清空构建缓存）；
- 匿名卷、24 小时前的临时目录。

这是唯一可以安全执行"激进清理"的窗口：没有题在跑，不存在误删。
之后启动下一个 chunk。

### 1.4 整批结束

`run_chunked.sh` 的最后一个 chunk 边界即整批结束，清理同上；协调器
`synthesize_batch` 自身也会在 wave 结束时做一次 `batch-end` 级别的清理。

## 2. 需要人工的三件事

1. **`harbor_export` 搬家**：静态交付数据，可 rsync 到 `/` 后软链接；不是清理动作；
2. **删除失败题目录**：会丢失证据，是否保留由审计需求决定；
3. **dockerd 重启**（幽灵容器 / containerd 元数据损坏）：影响所有在跑容器，只能择机。

## 3. 500 题分块 + 140 并发

```bash
scripts/run_chunked.sh samples/batch-02 results/batch-02 harbor_export/20261114-production \
    samples/batch-02/fresh-todo.txt 500 70
```

- 任务清单按行切成 `chunks/part-NNN`（每 500 道一份）；
- 每个 chunk 调 `start_dual.sh`：两个 daemon、**共享队列抢题**（`results/batch-02-claims`），
  每个 daemon **70 并发**，合计 140；
- 结果目录 `results/batch-02-a` / `-b`，发布目录 `harbor_export/..._1` / `_2`；
- chunk 之间自动全量清理（见 1.3），无需人工盯盘；
- 全部结束后把 `_2` 的题目录并入 `_1`，再跑 `scripts/refresh_exported_verifier.py`。

## 4. 容量估算

以 batch-02 为例（1952 题）：

| 项 | 估算 |
|---|---:|
| 输入 `samples/` | ~127G |
| 结果 `results/` | ~250–300G（每题 80–200M） |
| 交付 `harbor_export/` | ~350–400G（每题 ~350M） |
| docker 镜像峰值（140 并发） | 基础层 + 在跑题镜像，约 300–600G |
| 构建缓存 | 6h 窗口内 ~400–800G（`UNTIL=3h` 时减半） |

在 500 题分块 + chunk 边界全清的模式下，`/nvme` 峰值通常不超过 **2.5T**，
全程 3.5T 盘有 ~1T 余量。

## 5. 阈值告警口径

- `/nvme` 空闲 <300G：只做 per-task 清理（自动）；
- <150G：暂停调度（停止 coordinator）；
- <50G：停止批次并人工处理；
- 当前所有分块和 housekeeping 都会在到达这些线之前释放空间。