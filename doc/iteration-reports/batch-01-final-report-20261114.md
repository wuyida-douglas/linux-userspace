# batch-01 收尾报告（2026-11-14）

## 1. 总体结果（2000 道）

| 结果 | 数量 | 说明 |
|---|---:|---|
| passed | **984** | 49.2% |
| 路由拒绝（not_suitable） | 160 | 不计入成功率分母 |
| failed | 243 | review 拒绝 127、合成失败 26、harbor_failed 及杂项 |
| error | 338 | 验收 health 151、routing agent 13、input/rclone 145、其他 |
| 遗留 in-progress 记录 | 32 | harbor 31 + routing 1，无 worker |
| 清理期删除、未再重跑 | 243 | 按操作要求删除失败目录 |

- 1562 道 fresh（首次尝试）：第一轮 passed 462 + 第二轮（管线修复后重跑）passed 311 = **773**；
- 438 道此前已尝试：历史 passed 211；
- 合计 **984 / 2000 = 49.2%**。

## 2. 可回捞题目（613 道）

`samples/batch-01/salvage-todo.txt`

| 类别 | 数量 | 说明 |
|---|---:|---|
| harbor-infra | 180 | `Harbor trial failed`，其中 health 阶段 151（`target_unhealthy` 99 / `infra_error` 75 的大部分） |
| other-error | 145 | rclone 下载失败 / 无可用源码快照 137、PermissionError 等 |
| missing | 243 | 清理时删掉目录的失败题（原因未知，可直接重跑） |
| leftover | 32 | 卡在 harbor/routing 的遗留记录 |
| routing-agent | 13 | 路由 agent 超轮（新 prompt 与 60 轮上限已调整，可重跑） |

**这些题只能整题重跑**：`failed`/`error` 是终态，工作区要么已清理、要么处于半成品状态；`--only <task-id>` 会从路由开始完整重跑。建议低并发（20–30）分批跑，health 抖动会显著减少。

## 3. 各阶段耗时（passed 题，n=984）

| 阶段 | 中位 | p90 |
|---|---:|---:|
| route | 3.1 min | 7.2 min |
| synthesis | 34.0 min | 57.5 min |
| review | 16.1 min | 25.3 min |
| harbor（review 结束 → 验收结束） | 41.4 min | 98.6 min |
| **单题总计** | **84.2 min** | 137.5 min |

**能不能加并发？**
- 理论吞吐 = 并发 / 单题耗时：80 / 84min ≈ **57 题/小时**；实测 25–35 题/小时，差额来自 harbor 排队与阶段切换。
- 加并发的瓶颈不是 CPU（255 核、load ~100），而是**单 docker daemon**：并发 80 时 `compose up` 在高峰期从 20 秒退化到 60–100 秒，health 失败率同步上升（151 道题因此报废）。
- 若要提速，优先级：① 先回收 health 抖动（低并发补跑或增加探针预算）；② 再考虑 100 并发并观察 `compose up` p90；③ 真正规模化需要第二个 dockerd（独立 data-root/socket）。

## 4. 合成过程中的人工干预（不是一键跑完）

### 4.1 手动存储清理

| 时间(UTC) | 操作 | 效果 |
|---|---|---|
| 06:00 | `network prune --filter until=1h` | 892 → 135 网络，IPAM 快照 11.3s → 0.4s |
| 07:00 | `builder prune -af`（全量） | 1.6TB → 273GB |
| 09:00 | 清容器（含 225 个幽灵记录：停 dockerd、移走 `/nvme/docker/containers` 目录） | 容器清零 |
| 09:30 | 删 687 个失败题目录 + 全量清镜像/卷/临时目录 | `/nvme` 1.5T → 2.9T 空闲 |
| 20:21 | `builder prune --filter until=3h` | 1.78TB → 1.49TB（耗时 20 分钟） |
| 22:24 | `builder prune --filter until=3h` | 1.76TB → 1.61TB（8 分钟） |
| 23:04 | `network prune --filter until=30m` | 431 → 174 网络，`compose up` 从 106s 回落 |

### 4.2 手动重启批次（全部有原因）

| 时间 | 原因 | 代价 |
|---|---|---|
| 06:45 | 应用 900s 超时/网络清理等修复；77 道在途题标记 skipped | 丢弃 77 道在途工作 |
| 12:53 | 修 `FileNotFoundError`（共享镜像 manifest 命名），重置 7 道 | 重启时在途题重跑 |
| 13:18 | 修"agent 退出码 1 被当成验收失败"，重置 10 道 | 同上 |
| 16:33 | supervisor 被外部 SIGTERM（-15），手动拉起 | 无（接管在途） |
| 21:14–21:30 | 修 pid 复用幽灵槽位 + bounded-recovery 冻结问题，清 156 条 stale 记录后重启 | 156 道题从头重跑 |

## 5. 故障与修复清单

| # | 故障 | 根因 | 修复 |
|---|---|---|---|
| 1 | 根盘被 containerd 数据占满 | docker 数据在 `/dev/sda1` | `/nvme/containerd` bind mount + data-root=/nvme/docker（已迁移，不再重复） |
| 2 | 验收大量 420 秒超时 | docker 网络泄漏 892 个，IPAM 全量 inspect 11.3 秒/次并在全局锁内执行 | 清网络 + 探针 900 秒上限 + 每 30 分钟 housekeeping 清 >30 分钟死网络 |
| 3 | 镜像被 per-task 清理后重排必然失败 | 失败题重排 + 交付包不含构建上下文 | 禁止一切自动重排（`--retry-failed` 禁用、requeue 脚本删除） |
| 4 | "已验收却判 error"：`shared image archive differs` | `docker save` 输出随 daemon 状态变化，字节与已发布副本不同 | 从已发布目录播种 `shared-runtime`，后续题复用同一份归档 |
| 5 | `FileNotFoundError: verifier.tar.gz.tar.manifest.json` | 共享清单双命名，helper 收到完整文件名又拼后缀 | `shared_manifest_path` 先取 stem，兼容两种命名 + 单测 |
| 6 | 新验收设计下每题都失败 | 参考提交预置 + `--max-turns 1`，claude 以 1 退出，harbor 记 `NonZeroAgentExitCodeError` | 以 verifier 的数值 reward 为准，agent 异常降级为 warning |
| 7 | 151 道 health 失败（`target_unhealthy`） | 80 并发下服务启动/探针抖动（Jenkins 等需 1–2 分钟） | 探针改为在 `health_timeout_sec` 预算内每 10 秒重试 |
| 8 | 并发从 80 掉到 41，调度器不再补位 | pid 复用：`worker_alive` 只认进程名，不认任务 id | `worker_alive(pid, task)` 校验 `--only <task>` |
| 9 | 重启后在途题被永久冻结（158 道） | bounded recovery 把 `synthesizing+running` 的记录标 `manual_recovery_required` 并搁置 | 未完成且无活 worker 的题直接重新排队 |
| 10 | `/dev/null` 权限被改成 644 | 疑似有宿主权限的合成 agent 误改 | `chmod 666`；属宿主级风险，代码无法完全防护 |
| 11 | supervisor 收到无解释的 SIGTERM | 外部信号，日志无堆栈 | 手动重启并接管在途 worker；未复现 |
| 12 | 构建缓存持续增长吃盘 | 每题构建一次，缓存只在批次结束清理 | 30 分钟 housekeeping（<800G 触发、until=6h）+ 必要时手动 until=3h |
| 13 | 命名卷/agent 自建镜像/TMPDIR 残留 | `volume prune` 只管匿名卷；镜像/临时目录无人认领 | 新增 `prune_idle_volumes` / `prune_stale_images` / TMPDIR 全量清扫，30 分钟一轮 |