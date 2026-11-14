# 单 docker daemon 的容量与阻塞分析（2026-11-14）

## 1. daemon 在管线里做什么

每题在 dockerd 上的操作：

1. `docker build`：合成 agent 构建 main/client 镜像（中间层留在 buildkit 缓存）；
2. `docker save`：导出时把镜像打成 tar.gz；
3. `docker load`：验收前把归档灌回镜像存储；
4. `compose up`：每题 6 次（2 次 trial × 玩家环境 / vulnerable / fixed），每次包含建网络、建容器、启动、健康检查；
5. `docker exec`：健康探针、oracle、提交物执行；
6. `docker rm/network rm/image rm`：每题终态清理；
7. `builder prune` / `image prune`：定期回收。

这 7 类操作全部经由**同一个 dockerd 进程与其 containerd**，共享内容存储锁、网络/IPAM 状态和快照元数据。

## 2. 实测数据（本机，2026-11-13）

| 时间(UTC) | 网络数 | `compose up` 中位 | IPAM 快照 | 备注 |
|---|---:|---:|---:|---|
| 11-11 09:00 | — | 7 s | — | 低负载 |
| 11-13 05:30 | 892 | 350–640 s | **11.3 s** | 死网络占满子网池，IPAM 全局锁排队 |
| 11-13 06:12 | 135 | 16.5 s | 0.42 s | 清理死网络后 |
| 11-13 14:00 | ~110 | 8–20 s | 0.5 s | 干净环境 |
| 11-13 23:00 | 431 | **97–107 s** | ~2 s | 两小时内重新堆积 |
| 11-14 00:30 | 188 | ~20 s | 0.9 s | 手动清 431→174 后 |

其它观测：

- dockerd 自身 CPU **1800–2500%**（containerd 700%），load average 95–125（255 核）；
- `docker ps` 正常情况下 0.4 s，高负载时 1.4 s；
- 构建缓存 1.2–1.8 TB 时，`builder prune` 单次耗时 **8–20 分钟**，期间 `compose up` 出现 **319 s** 的离群值；
- 80 并发下每题 6 次 up，健康探针失败率 15–20%（服务启动被 CPU/IO 挤慢）。

## 3. 阻塞点（按影响排序）

1. **IPAM 全局锁 + 全量网络快照**：每次 `compose up` 都要在宿主机级 flock 内 `docker network inspect` 全部网络。网络数从 135 涨到 892，快照从 0.4 s 涨到 11.3 s，80 并发全部排队 → up 时间从 20 s 变 10 分钟。
2. **构建缓存 GC 与内容存储锁**：缓存到 1TB+ 后，buildkit GC 与手动 prune 持有内容存储锁数分钟，期间所有镜像层挂载/删除都变慢。
3. **网络/容器创建与 veth 抖动**：dmesg 显示 veth/bridge 高频创建销毁，dockerd CPU 高企；`compose up` 的固定开销约 10–20 s。
4. **每个 up 的 6 次容器生命周期**：即使 daemon 空闲，6 次 up + down 也要 1–2 分钟。
5. **健康检查等待**：服务就绪时间在负载下放大（Jenkins 1–2 分钟），探针抖动直接判废题目。

## 4. 已做的缓解

- 死网络 30 分钟清扫（`prune_idle_networks`，阈值 0.5 h）；
- 构建缓存 30 分钟清扫（空闲 <800G 且 >6h），必要时手动 `until=3h`；
- 每题终态删容器/网络/镜像；命名卷、旧镜像、TMPDIR 定期清扫；
- 验收 `compose up` 上限 900 s；健康探针在 300 s 预算内每 10 s 重试；
- IPAM 改为一次批量 snapshot（O(1) 次 daemon 调用），并按角色分池。

## 5. 若还要提速

**短期（不改架构）**

1. 把 `PIPELINE_BUILD_CACHE_PRUNE_UNTIL` 调到 3h、`MIN_FREE_GB` 调到 1200，让缓存稳定在 <600 GB；
2. 网络清扫阈值降到 15 分钟（当前 30 分钟），并在监控里把"网络数 >250"作为告警；
3. 合成 agent 的 `docker build` 加 `--build-arg BUILDKIT_INLINE_CACHE=1` 无益；真正有效的是**限制并发构建数**（例如同时最多 40 个 build），把 daemon 的 CPU 峰值压下来。

**中期（推荐）**

4. **第二个 dockerd**：独立 `data-root` + 独立 socket（如 `/run/docker2.sock`），合成构建走 daemon A、验收 compose 走 daemon B，锁互不影响；
5. 验收环境改成 **buildx `docker-container` driver**，缓存与 GC 由该 builder 自己的 buildkitd 管理，不占主 daemon 的内容存储锁。

**长期**

6. 验收容器跑在独立的轻量 VM/节点上（Harbor 本身支持远程 environment），彻底把"每题 6 次 up"的负载从主 daemon 移走；
7. 网络改用 host-local IPAM 插件预分配 /24，去掉全局 flock 与全量 inspect。

## 6. 结论

当前 80 并发下，单 daemon 的**安全上限约 80–100 个并发任务**；再高时瓶颈从模型侧转移到 daemon 侧
（up 时间、健康失败率同步上升）。在不引入第二个 daemon 的前提下，继续加大并发收益会递减。