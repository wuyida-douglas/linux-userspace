# 清理层级说明（2026-11-14）

管线里的清理分四层：**每题终态**、**每 30 分钟**、**整批结束**、**手工兜底**。
前两层已经覆盖了昨晚绝大多数手工作业；只有三类操作仍然需要人判断，列在最后。

## 1. 每题终态（`pipeline/run.py` → `resource_cleanup.cleanup_task`）

任务进入终态（passed/failed/error/timeout/skipped）后立即执行，并写 `cleanup.json`：

- 容器：按 `com.docker.compose.project.working_dir` 在题目录下、或 `pipeline.task=<id>` 匹配；
- 网络：working_dir 在题目录下的 Compose 网络（批量删除，失败记录在报告里）；
- 镜像：`task.json` 里声明的 agent/target/sidecar 镜像（`linux-userspace-*` 受保护）；
- 目录：`harbor/bundle`、`harbor/accept-profile`、`harbor/frozen-delivery`、
  `harbor/jobs/*/verifier/work`、`infrastructure-attempts`、`workspace/.agent-tmp`
  （root 文件回退：先 sudo，再起一个临时 root 容器删）。

## 2. 每 30 分钟 housekeeping（`synthesize_batch._housekeeping_loop`）

批次运行期间后台线程，启动 5 分钟后先跑一次，之后每 30 分钟：

| 动作 | 范围 | 阈值 |
|---|---|---|
| `prune_unused_volumes` | 匿名卷 | 立即 |
| `prune_idle_volumes(results)` | results 根目录下的 Compose 命名卷 | dangling 且 >30 分钟 |
| `prune_idle_networks(results)` | results 根目录下的 Compose 网络 | 无容器且 >30 分钟 |
| `prune_stale_images(12h)` | 无容器引用的旧镜像 | 创建 >12 小时，`linux-userspace-*` 受保护 |
| `prune_temp_leftovers(24h)` | TMPDIR 下所有条目 | >24 小时 |
| `prune_build_cache(6h)` | buildkit 缓存 | 仅当数据盘空闲 < `PIPELINE_BUILD_CACHE_PRUNE_MIN_FREE_GB`（默认 1500，本轮设 800） |

## 3. 整批结束（`synthesize_batch` 收尾）

- `prune_build_cache("1h")`、`prune_unused_volumes`、`prune_temp_leftovers(24)`。

## 4. 手工兜底（昨天的实际动作，哪些已自动化）

| 昨天的操作 | 现在是否自动 | 说明 |
|---|---|---|
| `network prune --filter until=1h/30m` | ✅ 已自动 | housekeeping 每 30 分钟清 >30 分钟的死网络；昨天手动是因为旧代码阈值是 2 小时 |
| `volume prune` / 命名卷 | ✅ 已自动 | `prune_idle_volumes` |
| 镜像清理 | ✅ 部分自动 | 每题删声明镜像 + 12 小时旧镜像清扫；**全量 `image prune -a` 仍需人工**（会删掉共享基础镜像） |
| build cache 全量 `-af` / `until=3h` | ⚠️ 部分自动 | 自动只在空闲 <800G 时清 >6h 的层；昨晚手动用 3h 是因为 6h 窗口回收太少。可把 `PIPELINE_BUILD_CACHE_PRUNE_UNTIL=3h` 写进启动脚本 |
| 删 687 个失败题目录 | ❌ 不自动 | 属数据保留策略，自动删除会丢掉失败证据 |
| 幽灵容器清理（停 dockerd 移目录） | ❌ 不自动 | containerd 元数据损坏后的修复，需停机，不能放进循环 |
| TMPDIR 清理 | ✅ 已自动 | 改成"所有 >24h 条目" |

### 建议的配置调整

启动脚本里已有：

```
PIPELINE_BUILD_CACHE_PRUNE_MIN_FREE_GB=800
PIPELINE_BUILD_CACHE_PRUNE_UNTIL=6h
```

若希望进一步减少手工，把 `UNTIL` 改成 `3h`（单题最长约 1 小时，3 小时窗口安全），
`MIN_FREE_GB` 调到 `1200`，让清理更早触发。

## 5. 仍然需要人判断的三件事

1. **全量镜像清理**：会连共享基础镜像一起删，需在批次间隙做；
2. **删除失败题目录**：会丢证据，需按批次的审计需求决定；
3. **dockerd 重启**（幽灵容器 / 元数据损坏）：会影响所有在跑任务，只能择机。

## 6. 随包（export）自带的内容

- 每题的 `harbor-runtime-profile/bin/` 自带 verifier 与 helper（`pass2fail_verifier.py`、
  `legacy_pass2fail_verifier.py`、`docker_ipam.py`、`pristine_binds.py`、`task_contract.py`）；
- verifier 改动后，用 `scripts/refresh_exported_verifier.py --root <published-root>` 批量刷新
  历史导出包（2026-11-14 已执行：998 个包中 764 个被更新，234 个本已是最新，报告见
  `harbor_export/20261111-production/verifier-refresh-report.json`）。