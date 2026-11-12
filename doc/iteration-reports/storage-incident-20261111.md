# 存储问题复盘：根盘被写满、NVMe 为什么会耗尽，以及每题自动清理

> 时间：2026-11-11 至 2026-11-12
> 范围：`/nvme/wuyida/新管线开发` 的 batch-01 合成（2000 道题，80 并发）
> 结论先行：根盘被写满是 **containerd 数据目录默认在根盘**；NVMe 不够用是 **镜像、build cache、容器写层和验收中间产物没有生命周期管理**。现在每题终态后会自动回收这些临时资源，只保留轨迹、工作区和交付包。

## 1. 机器磁盘现状

| 盘 | 大小 | 挂载点 | 用途 |
|---|---|---|---|
| `/dev/sda` | 893G | `/`（891.6G ext4）、`/boot`、`/boot/efi` | 操作系统、`/home`、`/etc`、`/var/log`、apt、系统服务 |
| `/dev/nvme0n1` | 3.5T | `/nvme`（xfs） | 所有重数据：containerd、Docker、代码仓库、results、harbor_export、TMPDIR |

关键配置（当前）：

```text
/etc/fstab
  /nvme/containerd   /var/lib/containerd   none   bind   0 0

/etc/docker/daemon.json
  "data-root": "/nvme/docker"
  "log-driver": "json-file"
  "log-opts": {"max-size": "100m", "max-file": "3"}
```

## 2. 第一次事故：根盘 100%

### 现象

- 根盘 `/dev/sda1` 使用率到 100%，shell、日志、apt、临时文件全部异常；
- `/nvme` 当时还有 700G+ 空闲，但系统仍然“磁盘满”。

### 根因

Docker 配了 `data-root=/nvme/docker`，但这台机器用的是 **containerd 镜像存储**。镜像层、容器快照实际写在 **containerd 的根目录 `/var/lib/containerd`**，而它一直是默认值 —— 在根盘上。

80 并发不断 build 镜像、起容器，containerd 在根盘写了 817G，把 `/dev/sda1` 写满。`DockerRootDir` 只管 Docker 自己的元数据和容器日志，管不到 containerd 的镜像/快照。

### 解决

1. 停合成、停 Docker/containerd；
2. 新建 `/nvme/containerd`，bind mount 到 `/var/lib/containerd`，写入 `/etc/fstab`（重启仍生效）；
3. 启动 Docker，重新 load 必要镜像（verifier、agent 基础镜像）；
4. 删除旧目录 `/var/lib/containerd.old`、旧 `/var/lib/docker`、迁移中途的 partial 目录。

结果：根盘使用率回到 8%，容器数据全部落在 NVMe。

## 3. 第二次问题：NVMe 从 740G 空闲掉到 440G

### 实测构成（2026-11-12 03:40 左右）

| 项目 | 占用 | 说明 |
|---|---:|---|
| build cache（`docker buildx du`） | **878G**（可回收 877G） | 合成阶段反复 build 产生的缓存 |
| Docker 镜像（1299 个） | **~1032G**（按镜像 size 标签求和） | 其中任务相关镜像 959 个、约 741G |
| 容器 | 830 个（479 运行中） | 每个容器有写层；日志 json-file 每容器最多 100MB×3 |
| `results/` | **779G** | 每题的 workspace、harbor jobs、验收 work 目录、bundle 里的镜像 tar |
| `harbor_export/` | 59G | 已发布交付包（这是要保留的产物） |
| 合计已用 | **3.1T / 3.5T** | 空闲 440G 左右 |

> 镜像 size 标签包含共享层，按标签求和会高估实际磁盘占用，但量级正确：**镜像和 build cache 是主要消耗，而不是日志**。

### 为什么“每题几个 G”的直觉不成立

一道题从合成到验收，实际会同时存在这些副本：

1. **两个镜像**：`<task>-main`（做题环境）和 `<task>-client`（target）。实测单题镜像约 **190–220MB**，`docker save` 出的 tar.gz 与镜像 `inspect` 大小几乎一致（例如 190MB 镜像 → 190MB tar.gz）。少数任务有 GB 级镜像（最大约 8G），但属例外；`docker images` 的 Size 标签会把共享基础层重复计入每个镜像，不能直接用来估算磁盘）。
2. **验收时还会 `docker load` bundle 里的 tar.gz**，产生同镜像的另一份 tag；
3. **两个差分 phase 各起一套 Compose**（client + runner + 可能的 sidecar），每套都产生容器写层；
4. **build cache**：合成 agent 反复 build、改 Dockerfile，每次尝试都留一层缓存；
5. **harbor jobs**：每题 1–2 次 attempt，每次一个 trial 目录（agent 轨迹、artifacts、verifier work）；`private-upload.tar` 单次可达 80MB+；
6. **bundle**：`docker save` 出来的 main/client tar.gz，动辄 1–3G/题；
7. **`infrastructure-attempts/`**：每次 `--resume` 会把旧的 `harbor/` 归档一份，单个题实测可达 3.3G（里面还带着旧 bundle）。

所以单题峰值 **5–20G** 是正常的；1959 道题如果都不清理，需要几十 TB。

### 为什么之前没有自动清理

- 流水线的 cleanup 只做 `docker compose down`（停容器），**不删镜像、不删 build cache、不删 harbor 的中间目录**；
- 验收失败/超时会被重排（`--resume`），同一题会再产生一轮镜像加载和 job 目录；
- `harbor_export` 是最终交付物，必须保留；但 `results/<task>/harbor/bundle` 里还有一份同样的镜像 tar.gz，属于重复；
- 没有磁盘生命周期策略，只能人工 `buildx prune`。

### 一次错误的临时处理（记录教训）

- 手工 `docker buildx prune` 回收了约 230G，但 prune 在高负载期间长时间持有 containerd 内容存储锁，导致 26 道正在验收的题在 `private_cleanup` 阶段拿到非预期错误码而被判 `infra_error`（已全部重排，无数据损失）。
- 结论：**清理必须在任务/阶段边界做，不能在验收高峰做全量 prune**。

## 4. 每道题清理前后的实测体积

清理前（含镜像、验收产物、历史 attempt）：

| 题目 | 总大小 | 说明 |
|---|---:|---|
| linux-013 | 3.1G | harbor 308M + infrastructure-attempts 3.3G + workspace 151M |
| linux-100 | 3.7G | 同上结构 |

清理后（只保留轨迹/工作区/证据）：

- 100 道题的样本：min 3MB、p25 35MB、**p50 103MB**、p90 468MB、max 12.8G；
- 典型构成：`workspace/` 141M（delivery + input）、`synthesis/` 15M、`review/` 7M、`route/` 5M、`harbor/jobs/` 0.5M、`infrastructure-attempts/` 1.4M（只留小文件）。

交付包 `harbor_export/<task>/` 约 **274MB/题**（主要是 main/client 的镜像 tar.gz，这是交付物本身）。

## 5. 自动清理（已实现）

### 代码位置

| 文件 | 作用 |
|---|---|
| `pipeline/resource_cleanup.py` | 清理实现：容器、网络、镜像、临时目录；支持 dry-run 和批量 |
| `pipeline/run.py` | `run_exclusive()` 在 `run_one()` 返回后立即调用 `cleanup_task()`；清理失败只记日志，不改判分 |
| `scripts/requeue_harbor_timeouts.py` | 基础设施失败重排（与本清理配套，保证重排时镜像还在） |

### 每个任务终态后自动执行

- **容器/网络**：按 `com.docker.compose.project.working_dir` 是否位于该题目录、或 `pipeline.task=<task>` 标签，`docker rm -f` / `docker network rm`；
- **镜像**：删除该题 delivery 里声明的 `<task>-main` 和 `<task>-client`；
  - **所有已结束的任务都删除**，包括 `error`、`timeout`、`harbor_failed`；
  - 只有仍在流程中的状态（`preparing`、`routing`、`synthesizing`、`reviewing`、`harbor`）保留镜像和临时目录；
  - 批次停止后如需回收这些“未完成”任务，用 `--include-in-flight`（把无 worker 的题按已结束处理）；
  - 共享基础镜像（`linux-userspace-agent*`、`linux-userspace-verifier*`）永不删除；
  - 注意：镜像删除后，这些题若以后要 `--resume` 重新验收，需要先从 delivery 重建镜像（目前没有自动重建路径）；
- **目录**：
  - `harbor/accept-profile`、`harbor/bundle`、`harbor/frozen-delivery`（都可从 delivery 重建）；
  - `harbor/jobs/*/*/verifier/work`（含 `private-upload.tar`、runner、environment）；
  - `infrastructure-attempts/*/bundle`、`*/accept-profile`、`*/jobs/*/*/verifier/work`；
  - 终态任务再删 `workspace/.agent-tmp`；
- **保留**：`workspace/delivery`、`workspace/input`、`route/`、`review/`、`synthesis/`、`result.json`、`retry-evidence/`、`harbor/jobs/*/{result.json,trial.log,verifier/evidence.json}`、`cleanup.json`。

### 使用方式

```bash
# 自动：每个 worker 结束时执行，无需干预
# 手动批量（对已结束的题补跑清理）
python -m pipeline.resource_cleanup --results results/batch-01 --dry-run
python -m pipeline.resource_cleanup --results results/batch-01
python -m pipeline.resource_cleanup --results results/batch-01 --only <task-id>
# 停止批次后：连未完成题和遗留容器一起清，并清 build cache
python -m pipeline.resource_cleanup --results results/batch-01 --include-in-flight --prune-cache
# 只清理并顺带清 build cache（必须在没有任务运行时）
python -m pipeline.resource_cleanup --results results/batch-01 --prune-cache --prune-until 1h
# 临时关闭
PIPELINE_KEEP_RESOURCES=1 ...
```

### 实测效果

- 单题：linux-013 从 **3.1G → 168M**；
- 全批 358 道终态题执行后：Docker 镜像 1299 → 约 980+，`results/` 从 947G 降到约 730G，`/nvme` 空闲从 **442G 回到 750G 以上**；
- 清理过程中没有任务被判分失败（清理与判分解耦）。

## 6. 清理后存储上还剩什么

### 6.1 每题常驻（必须保留）

| 内容 | 体积 | 说明 |
|---|---:|---|
| `results/<task>/workspace`（delivery、input） | 几十 MB – 几百 MB | 复现题目和重新验收所需 |
| `results/<task>/synthesis`、`review`、`route` | 几 MB | 合成/评审轨迹，审计和训练分析用 |
| `results/<task>/harbor/jobs/*` 的小文件 | < 1MB | 验收结论和证据 |
| `results/<task>/retry-evidence`、`cleanup.json` | < 1MB | 重排历史与清理记录 |
| `harbor_export/<task>/` | ~274MB | **交付包本身**（镜像 tar.gz + profile） |

合计约 **0.4–1GB/题**（sample 中位数 103MB + 交付包 274MB）。2000 道题约 **0.8–2TB**，3.5T 的 NVMe 可以容纳，但需要注意大源码树题目（样本最大 12.8G）。

### 6.2 任务运行期间的临时占用（结束后由自动清理回收）

- 两个任务镜像（1–8G/个）；
- 两个差分 phase 的容器与写层、verifier 的 runner/private 目录；
- 验收 bundle 与 `private-upload.tar`；
- 这些只在题目进行中存在，按 80 并发估算峰值仍有几百 G，属于正常运行时开销。

### 6.3 不会被自动清理、会随运行累积的

| 项目 | 说明 | 处理 |
|---|---|---|
| **build cache** | 合成阶段反复 build 产生；本次实测 878G、可回收 877G | **已自动化**：coordinator 在整批结束（无 worker、无验收）时执行 `docker builder prune --filter until=1h`，可用 `--no-prune-cache` 关闭。不在验收高峰执行，避免锁住 containerd 内容存储 |
| Docker 容器日志 | json-file 100MB×3/容器，随容器删除释放 | 已由 daemon.json 限流 |
| 共享基础镜像 | agent / verifier 基础镜像几个 GB | 常驻，不清理 |

### 6.4 容量预估（2000 道题）

- 常驻：results ~0.4–1.4T + harbor_export ~0.5–0.8T；
- 临时峰值：镜像 + 容器 + bundle ≈ 0.3–0.6T；
- **合计 ~1.5–2.5T**，在 3.5T NVMe 内可运行；build cache 是唯一没有上限的部分，需要后续决定是否加“批次级 prune”策略（本次按你的要求未做）。

## 7. 当前状态

- 合成已停止（coordinator、supervisor、全部 worker 和 harbor 进程均已终止）；
- 终态统计：**passed 211、rejected 53、failed 94、error 71、harbor（未完成）84**；
- 证据与工作区都保留在 `results/batch-01/`，可用原命令 `--resume` 继续；
- 遗留容器：479 个（其中约 277 个属于 batch-01 的 compose 项目、58 个是验收 root-helper），可在低峰时统一 `docker rm -f` 清理；
- `/nvme` 空闲约 750G，`/` 空闲 801G。
## 8. 为什么 results/batch-01 比 harbor_export 大这么多（2026-11-12 复盘）

同一批题，`harbor_export` 只有 89G，而清理前 `results/batch-01` 有 350G。实测构成：

| 目录 | 大小 | 性质 |
|---|---:|---|
| `.repair-20261111-174827/` | **211.8G** | 迁移事故时归档的 208 个旧任务目录；**208 个在 results 下都有同名新目录**，属于纯重复 |
| `workspace/.agent-tmp/` | **54.2G** | 合成阶段容器内构建的临时树，root 所有；`shutil.rmtree` 删不掉，需要 root 删除 |
| `workspace/input/` | 33.7G | 每题源码输入（合成/复现需要） |
| `workspace/delivery/` | 22.7G | 交付清单与项目文件（重验/重建镜像需要） |
| `synthesis/`、`review/`、`route/` | ~12G | 轨迹与评审证据 |
| `harbor/`、`infrastructure-attempts/` | ~3.8G | 验收 job 证据 |

而 `harbor_export/<task>/` 只有交付包本身（镜像 tar.gz ~190–220MB/题 × 225 题 + profile ≈ 89G）。
`results` 保留的是**过程数据**（输入源码、构建临时树、归档副本），`harbor_export` 保留的是**结果数据**，两者不是同一层东西。

### 已修复

- `.agent-tmp` 清不掉的原因：目录里有容器构建产生的 root 文件，`shutil.rmtree` 静默失败。现在 `resource_cleanup._remove_tree()` 会回退到 `sudo -n rm -rf`，再回退到用容器 root 删除；实测单题 13G 的 `.agent-tmp` 0.7 秒清完，全批 54G 已回收。
- `trashcan/`（441G 旧迭代归档）已清空。

### 仍可回收

- `.repair-20261111-174827/` 211.8G：208 个目录全部有同名活动目录，是纯重复归档；删除后 results 约 84G。
