# 隔夜合成与错题分析（2026-11-11）

> 运行：`results/iterate-20261110-04` ～ `-09`
> 样本：`samples/iterate-20261109-s20261110`
> 模型：`glm-5.3`；并发 30–40
> 结论：04–07 终态 fresh **64/99 = 64.6%**；管线主要故障已修；**4 个 FILE-POV 失败是 verifier 没把输入路径传给 oracle（可一改恢复）**，**331 是 `private/` 子串误报**，不是题目质量问题。

---

## 0. 停止状态

- batch 08 supervisor `2251078`、batch 09 supervisor `2959209` 已停；所有 `pipeline.run` / `claude` worker 已清理。
- 监控 cron `959c78fe` 已删除。
- 收尾时发现 batch 07 任务 `352` 残留一个 `fwproxy.py`（PID `1255346`），已 kill；现在没有本批次的 `pipeline.run` / `supervise.py` / `batch-001` 进程。
- 02/03 的旧进程此前已清理；当前只剩本会话自身的 Claude 进程。

## 1. 批次结果

### 1.1 终态批次（04–07）

| 批次 | fresh | passed | failed | error | rejected | 非 rejected 分母 | 成功率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 04 | 30 | 16 | 5 | 3 | 6 | 24 | **66.7%** |
| 05 | 21 | 14 | 3 | 3 | 1 | 20 | **70.0%** |
| 06 | 30 | 14 | 4 | 9 | 3 | 27 | **51.9%** |
| 07 | 30 | 20 | 5 | 3 | 2 | 28 | **71.4%** |
| **合计** | **111** | **64** | **17** | **18** | **12** | **99** | **64.6%** |

- 目标 >60% 已达成；05/07 明显高于目标。
- 06 被 route 的 45-turn 预算拖累（9 个 error 中 5 个是 route 46 turns），这是管线 bug，不是题目质量；`6e61ef7` 改 60 后，batch 09 的 30 道 route **全部正常**。
- batch 04 里的 `101/125/130/136/145/148` 是 batch 03 的 carry 副本，不计入 fresh；`125/130/145` 在 batch 03 的 harbor-only retry 中已 passed，`101/136/148` 仍 pending（client unhealthy），`080` 旧 harbor 状态，`098/119/135` 的 review 进程死亡后 `review/result.json` 一直 running（stuck >90 min）。

### 1.2 停止批次（08–09）

| 批次 | passed | failed | error | rejected | synth | review | harbor | 说明 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| 08 | 12 | 4 | 2 | 4 | 3 | 3 | 2 | 停在 12/26 ≈ 46.2%，未终态 |
| 09 | 0 | 0 | 0 | 0 | 24 | 5 | 1 | 30 道全部进入 synth 以后，0 个 route error |

batch 08 的失败：`299`（review 拒绝，伪造日志可得分）、`308/312/319`（harbor miss）、`326/327`（harbor trial 异常）。
batch 09 停在合成中段，结果不足以评估成功率，但验证了 **route 60 turns 修复有效**。

### 1.3 P0 修复后的可恢复量（未重测）

如果下面 3.1/3.2/3.3 的 P0 修掉并只重跑受影响任务：

| 批次 | 现状 | 可恢复 | 修复后预期 |
|---|---:|---:|---:|
| 04 | 16/24 | `128/158/164` | 19/24 = 79.2% |
| 05 | 14/20 | `182` | 15/20 = 75.0% |
| 07 | 20/28 | `331` | 21/28 = 75.0% |
| 合计 | 64/99 | 5 | **69/99 = 69.7%** |

`366`（review JSON 坏了）如果 retry 也可能恢复；`365/371/377/355/356/326/327/192/25533/54059` 属于 harbor trial 簇，尚未逐题定因，暂不计入。

## 2. 管线修复清单（详细版）

这一节按“现象 → 诊断 → 根因 → 修法 → 验证 → 影响”展开，方便没有上下文的同学理解每个 commit 为什么存在。下面先给索引，细节在 2.1–2.8。

| 提交 | 一句话 | 类型 |
|---|---|---|
| `663d81d` | Claude Code 的 `--settings`/`--debug-file`/`--plugin-dir` 相对路径在 workspace cwd 下失效 | 基础设施 bug |
| `c4ee0f6` / `6fe0540` / `9e8f6b5` / `4f4ae47` | acceptance 的 reference 没有被 Harbor 收集，四个 commit 是同一链路的连续定位 | acceptance bug |
| `47058bb` | verifier 超时路径把 bytes 和 str 拼在一起，抛 `TypeError` | verifier 健壮性 |
| `d170916` | carry 复制旧 workspace 时被 root-owned 的 `.agent-tmp` 挡住 | carry bug |
| `6e61ef7` / `53a9aaa` | route 45 turns、accept 3 turns 预算不够 | 预算校准 |
| `715cf20` | review/synthesis 没检查可做性、自洽、oracle 归因 | prompt 质量 |
| `39b49de` | batch 04 没有批次报告 | 文档 |
| 运维 | 根盘 98% full，镜像 load 失败 | 运维 |

### 2.1 `663d81d` — Claude Code 路径参数在 workspace cwd 下失效

**现象**：batch 02 的 30 个 route 全部起不来，CLI 报 `Settings file not found`，路由阶段整体挂掉。表面上看像是 route 质量差或模型不工作，实际上是路径问题，route 根本没有正常启动。

**诊断**：agent 的 `cwd` 是 `.../<task>/workspace`，而 `pipeline/agent.py` 的 `command()` 把 `--settings agent-guard.json` 原样传给 CLI；Claude Code 按自己的 cwd 解析相对路径，于是去找 `workspace/agent-guard.json`，但文件实际在 `.../synthesis/agent-guard.json`。`--debug-file cli-debug.log` 和 `--plugin-dir config` 也有同样的相对路径风险，只是在 route 阶段先被 settings 暴露出来。

**根因**：`command()` 没有对传入路径做 `resolve()`，`run()` 也没有把 `workspace`、`output`、`network` 统一成绝对路径；pipeline 进程的 cwd 和 CLI 的 cwd 不同，相对路径在两侧含义不一致。

**修法**：`command()` 对 `debug_file`、`network`、`settings` 全部 `Path(...).resolve()`；`run()` 开头把 `workspace`、`output`、`network` resolve；这样传给 CLI 的路径全部是绝对路径，CLI 在 `cwd=workspace` 下也不会再找错。

**验证**：pilot route 343s/34 turns 成功；batch 03 起 route 恢复正常；batch 09 的 30 道 route 全部完成、0 route error。

**影响**：这是基础设施级修复。没有它，任意 stage 的 agent 都可能因为路径找不到而失败，而且会被误判成“模型不行”或“题目不可做”，掩盖真正原因。

### 2.2 `c4ee0f6` / `6fe0540` / `9e8f6b5` / `4f4ae47` — acceptance reference 收集链路

**现象**：batch 04 前期 acceptance 的 reference 提交没有被 Harbor 收集；agent 复制到 `/workspace/<submission>` 的是空目录；verifier 看不到提交，16 道 fresh 的 acceptance 失败。这四个 commit 不是四个独立 bug，而是同一个问题的连续定位过程。

**诊断**（按时间顺序）：

1. `c4ee0f6` 先把 reference 放到只读的 `/opt/reference/<submission>`，要求 agent `cp` 到 `/workspace/<submission>`，解决“reference 没被 Harbor 收集”；
2. `6fe0540` 把 mount target 改到 `/tmp/reference_<submission>`，怀疑目录 mount 有问题；
3. `9e8f6b5` 确认 Docker 对“不存在的单文件 bind target”会创建一个空目录，而不是报错，于是改成 mount 一个真实目录 `/opt/reference`，并把 reference 复制到 `reference_dir/<submission>`；
4. `4f4ae47` 最终发现 `bundle`/`accept_profile` 是相对路径，Harbor 从自己的 cwd 解析 bind source，相对路径会静默变成空目录；全部 `.resolve()`。

**根因**：Harbor/Compose 的 bind source 解析依赖调用方 cwd；单文件 bind target 不存在时 Docker 不报错而是建空目录；reference 必须出现在 agent 的 `/workspace` 下才会被收集。三个条件叠加，导致“看起来 mount 了，实际是空的”。

**修法**：`profile`/`accept_profile` resolve；reference 复制到 `accept-profile/tests/private/reference/<submission>`；mount 目录 `/opt/reference`；instruction 改成“从 `/opt/reference` cp 到 `/workspace`”；no-op acceptance prompt + `accept_turns=8`。

**验证**：batch 04 的 16 道 fresh 全部新 acceptance 2×1.0；187/190 修复后 2×1.0。

**影响**：这四条要一起看；单独看任何一个 commit 都像“改了个路径”，实际上是 acceptance 能否收集 reference 的完整链路。后续任何改动 mount/收集逻辑，都要同时回归“目录 mount、绝对 source、cp 到 workspace、两次 1.0”。

### 2.3 `47058bb` — verifier `TimeoutExpired` 的 bytes/str 拼接

**现象**：187/190 验收失败，pipeline 抛 `TypeError: can't concat str to bytes`，不是题目失败，也不是 verifier 判 0，而是 verifier 自己崩了。

**诊断**：`subprocess.run(text=True)` 在正常返回时把 stdout/stderr 解码成 str；但在超时抛 `subprocess.TimeoutExpired` 时，`exc.stdout`/`exc.stderr` 仍然是 bytes（CPython 行为）。`bounded_run` 的超时分支写的是 `(exc.stdout or "") + (exc.stderr or "")`，于是 str 和 bytes 直接拼接，抛 `TypeError`。

**根因**：没有统一 bytes/str；超时路径平时很少走，所以一直没暴露，直到 187/190 的 verifier 真的超时。

**修法**：新增 `_as_text()`：`None -> ""`，`bytes -> value.decode("utf-8", "replace")`，其他 `str(value)`；超时分支改成 `_as_text(exc.stdout) + _as_text(exc.stderr)`，返回 code 124。

**验证**：187/190 修复后 2×1.0；后续 verifier 超时不再因自身异常被记成 pipeline error。

**影响**：verifier 健壮性修复。没有它，任何 verifier 超时都会被误判为题目/管线错误，掩盖真实原因；而且这类错误只在负载高、任务慢时出现，很难复现。187/190 是 FILE-POV 的超时任务，verifier 本来应该返回 code 124 并记录输出；因为拼接崩了，pipeline 只看到 TypeError，无法区分“任务超时”和“verifier 自身坏了”。修复后 `_as_text` 也用于其他异常路径，保证错误信息能落盘。

### 2.4 `d170916` — carry 复制旧 workspace 时的权限

**现象**：batch 04 carry 旧任务时，`copytree` 在 `.agent-tmp/root/vuln` 报 `Permission denied`，carry 直接失败；后续只能重跑旧题。

**诊断**：旧 workspace 的 `.agent-tmp` 里有 root-owned 的容器挂载/构建产物（agent 用 docker-as-root 创建），wuyida 读不了；`harbor/` 里也有类似 root-owned 文件。carry 只需要 `input/`、`delivery/`、`route/`、`review/` 等任务证据，不需要 scratch 和旧 harbor。

**根因**：`shutil.copytree` 默认复制所有文件，没有 ignore；carry 的源目录混入了不可读的运行时残留。

**修法**：`copytree(..., ignore=shutil.ignore_patterns(".agent-tmp", ".agent-config", ".agent-home", "cli-debug.log", "latest", "__pycache__", ".pytest_cache", "*.pyc", ".agent-guard.log", "harbor"))`。

**验证**：batch 04 carry 正常；carry manifest 完整，`delivery/input/route/review` 没丢。

**影响**：carry 是跨批迭代的关键路径；不修就只能重跑旧题，浪费并发额度和时间，也会让“携带题”统计失真。另外，`copytree` 仍保留 `symlinks=True`，不会把旧 workspace 里的符号链接展开；但 `.agent-tmp` 里可能包含指向容器/宿主路径的 symlink，忽略整个目录也避免了把外部路径带进新任务。carry 只复制任务证据，不复制运行时残留，这是有意的边界。

**carry 的边界（避免误解）**：这里的 carry 是控制器的 `--carry-results`，不是合成 agent 去读旧题；它只用于 review/harbor 续跑，复制的是同一 instance 的任务目录。当前 ignore 只排除 scratch（`.agent-tmp`/`.agent-config`/`.agent-home`/`harbor` 等），仍会复制 `delivery/`、`synthesis/`、`review/`；因为 review 按设计要读合成轨迹（`pipeline/prompts.py` 的 REVIEW 明确提到 `live.chat.md`）。如果“连 review 也不允许看旧轨迹”也是你的设计，需要另外改 review prompt + 把 `synthesis/`/`review/` 加进 carry ignore；否则不要动 carry 的 delivery 证据。

### 2.5 `6e61ef7` / `53a9aaa` — route 和 accept 的 turn 预算

**现象**：batch 05/06 有 7 题 route = `agent_error, 46 turns`，旧预算 45；`193` rc=1、elapsed 295s；stderr 还有 `[claude-code:unrecognized_model]` 警告。accept 侧 3 turns 也不够：`linux-081` 的 acceptance agent 跑到 `max_turns`，Harbor 抛 `NonZeroAgentExitCodeError`。

**诊断**：46 > 45 是 route 的直接原因；route 在复杂题上需要更多 turn 做证据检查。accept 3 turns 对“读 reference、cp 到 workspace、确认”也不够；模型在 3 turns 内没完成 no-op 任务。`unrecognized_model` 只是警告，不是唯一原因，但说明当时还有环境噪音。

**根因**：预算是拍脑袋的 45/3，没有按实际 turn 分布校准；route 失败被误判成题目不可做，accept 失败被误判成验收基础设施坏。

**修法**：`6e61ef7` 把 `--route-turns` 45→60（`run.py`/`supervise.py` 默认都改）；`53a9aaa` 把 `accept_turns` 3→8，并加 no-op acceptance prompt。

**验证**：batch 09 的 30 道 route 全部完成、0 route error；accept 不再因 3 turns 异常。

**影响**：直接提升 route 成功率；但不要顺势把 400 也调大，那会掩盖真正的卡死。预算是“校准值”，不是越大越好。route 和 accept 是两条独立的预算：route 失败会让题目直接不进 synthesis；accept 失败只影响验收。两者被同一张表记录，但修复 commit 不同（`6e61ef7` vs `53a9aaa`），复盘时要分开看。

### 2.6 `715cf20` — review/synthesis 的可做性、自洽、oracle 归因

**现象**：194/299/375 这类题在 pass2fail 能过或看似能过，但题目其实不可做或有因果缺陷：194 的 healthcheck 在 verifier 的非 root runner 下必然失败；299 的 oracle 信任提交物 stdout，伪造输入可得分；375 的 target 镜像根本不存在，synthesis 没做完。

**诊断**：旧 prompt 只要求“pass2fail”，没有要求 review 检查 main 是否有 instruction 声称的源码/工具、SVC 从 main 是否可达 target、oracle 是否把效果归因到 CVE、负控是否 absent。

**根因**：review 的检查项与“题目可解性/因果性”脱节；verifier 设计得再好，题不可做也没用。

**修法**：SYNTHESIZE + REVIEW prompt 增加 solvability、self-consistency、CVE-attributed oracle、negative control；review 必须检查 main 的源码/工具/endpoint；oracle 不能先自己 probe 再只看日志；负控必须 absent；review 只读，不改 delivery。

**验证**：后续 review 抓到 194/299/375；这三题记为题目缺陷，不是管线失败。

**影响**：提高交付质量，减少“verifier 过但题不可做”；代价是 review 更严格，可能增加 reject。需要在“严格”和“吞吐”之间继续校准。

### 2.7 `39b49de` — batch 04 批次报告

**现象**：batch 04 没有批次报告，失败原因和 carry 关系只散落在 `result.json` / `supervisor.log` 里，后续复盘成本高。

**诊断**：批次结束后没有固定模板记录 fresh/passed/failed/error/rejected、失败分类、证据路径；下一批只能靠翻目录。

**修法**：新增 `doc/iteration-reports/iterate-20261110-04-batch-001.md`，按批次记录状态、失败分类、关键证据。

**验证**：报告和 `result.json` 一致；后续 overnight summary 和错题分析都以它为输入。

**影响**：只是文档，不改代码；但没有它，后续无法区分“管线 bug / 题目缺陷 / 模型打转”，容易误判，也会重复踩同样的坑。报告至少应包含：批次号、fresh/carried 列表、每题状态、失败分类（pipeline/题目/模型）、关键证据路径、可恢复建议。它不是为了好看，而是为了让下一批的 `--only`/`--carry-results` 选择和错题归因有依据；没有报告，batch 04 的 carry 关系只能靠人翻目录。

### 2.8 运维 — 根盘 98% full

**现象**：根盘（`/dev/sda1`，不是 NVMe）98% full；`docker load` 报 `no space left on device`；batch 04 前后大量镜像/容器/构建缓存堆积，后续 acceptance/load 失败。

**诊断**：30–40 并发、每题多镜像、失败任务的容器和 builder cache 不自动清理；`docker container prune` 释放 57.45GB，image prune/builder prune 又释放数百 GB。

**根因**：没有批次前后清理策略；失败任务残留容器/镜像长期占用根盘。

**修法**：手动 prune 恢复；建议在批次前后加清理脚本/监控（容器、悬空镜像、builder cache、旧 bundle）。

**验证**：根盘恢复数百 GB，后续 load/acceptance 正常。

**为什么 NVMe 很大还会满**：`df -h` 显示 `/` 是 `/dev/sda1`（864G，当前 545G used / 64%），`/nvme` 是 `/dev/nvme0n1`（3.5T，1.9T used / 52%）；`docker info` 的 `Docker Root Dir` 是 `/var/lib/docker`，它在 `/dev/sda1` 上，**不在 NVMe**。合成 workspace/results 确实在 `/nvme`，但 Docker 镜像/容器/build cache 在根盘，所以根盘会先满。

**当前 Docker 占用（`docker system df`）**：Images 335 个 / 494.1GB（341GB reclaimable）；Containers 134 个 / 18.21GB（286.2MB reclaimable）；Local Volumes 165 个 / 15.87GB（15.27GB reclaimable）；Build Cache 3082 条 / 348.6GB（25.9GB reclaimable）。清理后根盘是 64% used（545G/864G），之前是 98%。

**有没有自动回收**：管线代码**没有全局** `docker system prune` / image prune / builder prune。只有 `pass2fail_verifier`/`harbor` 对自己创建的 compose project 做 `docker compose down --volumes` / `docker rm`，以及 verifier 的 private cleanup；**镜像和 build cache 不会自动回收**。所以 335 images / 3082 cache 会长期堆积，需要批次级清理，或把 Docker `data-root` 迁到 NVMe。

**影响**：不清理会直接让后续批次失败；这是运维项，不是代码 bug，但优先级很高，应该像“检查 supervisor 已停”一样纳入批次收尾 checklist。实际命令包括 `docker container prune -f`、`docker image prune -af`、`docker builder prune -af`；清理前要先确认没有本批次正在跑的 `pipeline.run`/`supervise`，避免误删正在用的容器。建议在批次收尾 checklist 里加一条“根盘使用率 < 80%”，并在批次开始前预检。

### 2.9 交付扫描/校验清单（run.py + harbor + task_contract）

这一节回答“run.py 到底扫了什么、还可能误杀什么”。先分清两类：**结构性校验**（解析 YAML/JSON、检查字段/路径/镜像）一般不会因为一句文案误杀；**子串扫描**（对整段文本做 `in`/regex）才是误杀高风险。

**`run.py::validate_delivery()` 在导出前做的事**：

1. **必需文件/目录存在**：`task.json`、`private/healthcheck.sh`、`private/oracle.sh`、`private/solution.sh`、`private/gold`、`instruction.md`、`environment/docker-compose.yaml`、`project`。缺一个就拒绝。
2. **symlink 安全**：遍历 `delivery/`；绝对 symlink，或 resolve 后跑出 `delivery/` 的 symlink，直接拒绝。相对且 resolve 在 `delivery/` 内的 symlink 允许。
3. **`load_task(task.json)`**：schema_version=1；branch/host_type/interaction/submission_mode 匹配；`images.agent`/`images.target` 非空、不相等、符合 image 正则、不含 `..`；`runner.user` 必须是非 root 的显式 uid/gid；`runner.workdir=/workspace`；healthcheck/oracle/solution argv 合法；FILE-POV 的 `public_runner.argv` 必须含 `{input}`；sidecar 名字不能是 main/client/runner。
4. **`validate_route(route.json)`**：instance_id 必须匹配；accepted 是 bool；SVC 必须有合法 host_type，FILE 分支 host_type 必须 null；reason 非空。旧 route 字段兼容。
5. **`recovery_required=true`**：必须有 `delivery/project/source-recovery.json`，否则拒绝。
6. **Compose 结构**：必须能匹配 `^  main:`；services 必须包含 main+client，不能有 runner；client.image 必须等于 `task.json.images.target`。
7. **`validate_public_services(services)`**（在 `harbor.py`，run.py 调用）：main/client 镜像必须不同且非空；不能有 static IP（顶层或 network attachment）；不能有 `ports`；不能有 `build/privileged/pid/network_mode/cap_add/cap_drop/devices/security_opt/cgroup_parent/ipc/uts/container_name`；不能有 `HTTP_PROXY/HTTPS_PROXY/NO_PROXY` 等 proxy env；每个 service 必须有启用的 healthcheck 且 `test` 非空；volume source 必须是 `./...`。**2026-11-11 已删除 volume source 的 `private/gold/fixed/docker.sock` 子串检查**，改由 REVIEW prompt 检查。
8. **整份 Compose 子串扫描**：`forbidden = ["private/", "../private", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "/var/run/docker.sock", "/run/docker.sock"]`，对 **compose 全文**做 `in`。这是 §3.2 的 331 误报来源：`/vault/private/ready` 也会命中 `private/`。
9. **legacy 材料存在性**：`public_tests`、`private/verify.sh`、`private/solve.sh` 存在就拒绝。
10. **gold 存在性**：`private/gold/<submission_mode>` 必须是文件。
11. **`frozen_inventory(delivery)`**：对 delivery 全量 hash（排除 `.git`/`.agent-tmp`/`__pycache__`/`.pytest_cache`），review 前后必须完全一致；review 只要写了其他文件，就会被判“review modified the submitted delivery”。

**`harbor.py::read_public_compose()` 在导出/验收时还会做**：

- network 不能是 `external`、不能有显式 `name`、不能带 `ipam.config`（防止开发态 subnet 泄漏）；
- client.image 必须等于 `images.target`；main.image 必须是 `null` 或 `images.agent`；
- volume 的 `./` 资源必须真的在 `environment/` 下，且 source 不能含 `private/gold/fixed/docker.sock`；
- 对所有 image 做 `docker image inspect`，不存在就拒绝。

**`run.py::review()`**：`workspace/review.json` 必须是合法 JSON，且键精确为 `{passed, evidence}`（`passed` bool、`evidence` 非空字符串）；旧的 `{passed, findings, reason, execution_checked}` 兼容。多写一个 `notes`/`severity` 字段会被拒绝。

**`run.py::route()`**：`route.json` 必须是合法 JSON；instance_id/branch/host_type/reason 校验；拒绝的 route 必须 `branch=null`。

**误杀风险排序（你重点看这几个）**：

1. **整份 Compose 的 `private/` 子串（已删除）**：331 已经踩到；现在不再全文 `in`，改由 REVIEW prompt 检查真实 bind source 和凭据。
2. **volume source 子串（已删除）**：`./fixed-assets`、`./private-data` 这类合法公共资源不再被误杀；现在只保留 `./` 和 `safe_asset` 结构检查，真实泄漏由 REVIEW prompt 检查。
3. **`review.json` 键必须精确（已放宽）**：现在只要求 `passed` 是 bool、`evidence` 是非空字符串；额外字段（如 `notes`）会被忽略，不再拒绝。
4. **`frozen_inventory` 任何写入**：review 的 `git status`/`git diff` 会改 `.git/index`（已排除），但 review 如果写 `notes.md`、`review-input/` 之外的文件，会被判 delivery modified；这是有意的只读保护。
5. **`healthcheck` argv 白名单**：只允许 `/healthcheck.sh`（或旧 `/private/healthcheck.sh`、`/opt/healthcheck/check.sh`）；自定义路径会被拒。
6. **image 正则**：只允许小写、可带 `:tag` 的引用，且不能有 `..`；大写或 digest 形式可能被拒。
7. **`main.image` 必须是 null 或 `images.agent`**：任务专用 main 必须 retag 成 `images.agent`，否则拒绝。

其余 1–7、`read_public_compose` 的结构检查是“契约校验”，误杀通常是任务真的不符合契约（例如 public compose 里写了 `build:`、端口、root runner、静态 IP），不是一句文案造成的。

## 3. 错题分析

### 3.1 P0：FILE-POV verifier 没把输入路径传给 oracle（128/158/164/182）

这 4 道不是“gold 在新环境不触发”，而是 **oracle 根本拿不到 verifier 已经复制好的输入文件**。

证据：

- `128` 的 `evidence.json`：
  `vulnerable.oracle.returncode=1`，`output="oracle: submission input not found"`；`argv` 是
  `docker compose ... exec -T client /private/oracle.sh`，**没有 argv[1]**。
- `128` 的 `oracle.sh:34` 明明支持 `SUB="${1:-}"`，但后面的候选列表只有
  `/input.bin /input/input.bin /submission/input.bin /submission /tmp/input.bin /workspace/input.bin /root/input.bin ...`，
  **没有 `/run/pass2fail/input.bin`**。
- `pipeline/pass2fail_verifier.py:634` 在 FILE-POV 分支把输入 `docker cp` 到
  `client:/run/pass2fail/input.bin`；但 `:680` 调 oracle 时只传
  `["/private/oracle.sh"]`，没有把 `destination` 传进去。
- `158` 同样支持 `"${1:-}"`，同样没收到 arg，`status=miss`、`returncode=1`。
- `164` 的输出是
  `[oracle] effect ABSENT (runner rc=1): !! infile cannot be read: /private/reference/input.bin`。
  它兜底 `find / ... /private` 找到了 `/private/reference/input.bin`，但该目录 `drwxr-x---`（wuyida 属主），
  runner uid 65534 无法穿越；如果收到 `/run/pass2fail/input.bin`（docker cp 出来是 root 0644），就能读。
- `182`（`osv-2020-1266-file-pov`）输出
  `oracle: submission input not found`，`exit 3`；oracle 的候选是
  `"${1:-}" /input.bin /workspace/input.bin /var/arrow-run/input.bin /tmp/input.bin`，
  同样没有 `/run/pass2fail/input.bin`，同样没收到 arg。

**根因**：verifier 的 FILE-POV 输入路径约定是 `/run/pass2fail/input.bin`，但 oracle 调用没带这个参数；
题目 oracle 都预留了 `$1`，是管线没喂。**一行修复**：

```python
oracle_argv = list(self.contract["oracle"]["argv"])
if self.contract["branch"] == "FILE-POV":
    oracle_argv.append(destination)          # /run/pass2fail/input.bin
record["oracle"] = self.compose(project, "exec", "-T", "client", *oracle_argv,
                                timeout=self.contract["runner"]["timeout_sec"] + 30)
```

并加一条回归：FILE-POV 的 `oracle.sh` 必须能用 `$1` 读到 gold，且 runner uid 可读。
修复后用 harbor-only `--resume` 重跑 `128/158/164/182`，不要重跑整批。

**责任划分（回答“是不是 prompt 的问题”）**：这不是单纯的 prompt 问题，而是 verifier 契约和 oracle 实现没有对齐：
verifier 把输入放到 `/run/pass2fail/input.bin` 却不传 argv；oracle 端预留了 `$1`，但候选列表没有这个路径。
所以两边都要修：verifier 传 `$1`（主修），prompt 写死路径契约（防复发）。

**当前状态（2026-11-11）**：上面的修复已落地——`pipeline/pass2fail_verifier.py` 新增
`oracle_argv_for()`，FILE-POV 自动 append `/run/pass2fail/input.bin`；`pipeline/prompts.py` 和
`doc/pipeline-prompts.md` 明确 oracle 必须接受 `$1`；新增 `tests/test_pass2fail_oracle_argv.py`（3 个用例）。
全量单测 `121 tests OK`。`128/158/164/182` 还没重跑，修后走 harbor-only resume。

> 更正：`doc/iteration-reports/iterate-20261110-04-batch-001.md:28` 写的
> “128/158/164：gold 在新环境不触发（task-specific）”是误诊。证据指向 verifier 参数缺失，
> 不是题目本身不触发。

### 3.2 P0：`private/` 子串误报（331）

`331`（`cve-2021-29653-svc-exploit-native-service`）报：

```text
ValueError: public Compose contains forbidden material: private/
```

`pipeline/run.py:226-230` 是对整份 compose 文本做子串扫描：

```python
forbidden = ["private/", "../private", "ANTHROPIC_AUTH_TOKEN", ...]
for token in forbidden:
    if token in compose:
        raise ValueError(...)
```

而 `331` 的 compose 第 22 行是合法的 Vault sidecar healthcheck：

```yaml
test: ["CMD", "bash", "-c", "test -f /vault/private/ready && curl -fsS ..."]
```

`/vault/private/ready` 里的 `private/` 是容器内公共路径，不是交付目录的 `private/`。
这是**管线误报**，题目本身大概率没问题。

修法：不要对整份 compose 做子串扫描；只检查 **bind source 字段**（`validate_public_services()` 已经在做）
和交付目录相对引用，允许 `/vault/...` 这类容器内绝对路径。加一条回归：healthcheck 命令里出现
`/vault/private/ready` 不应被拒。修复后 retry `331`。

**当前状态（2026-11-11）**：已按“会误杀的都放开”处理——删除 `run.py` 的整份 Compose `forbidden`
子串扫描；删除 `validate_public_services`/`read_public_compose` 里 volume source 的
`private/gold/fixed/docker.sock` 子串检查（保留 `./` 和 `safe_asset` 结构检查）；`review.json`
允许额外字段。真实泄漏改由 **REVIEW prompt** 检查：bind source 必须在 `./` 环境资产内，不能绑
private/gold/fixed/docker.sock、host 路径、`ANTHROPIC_*` 凭据；容器内 healthcheck 路径如
`/vault/private/ready` 明确允许。已加回归 `test_public_assets_are_not_rejected_by_name_substrings`。

### 3.3 P1：review 输出不是合法 JSON（366）

`366`（`cve-2020-7781-svc-exploit-synthetic-host`）报：

```text
JSONDecodeError: Expecting ',' delimiter: line 3 column 669 (char 688)
```

坏文件是 `workspace/review.json`（`task.json` 本身是好的）。review agent 写出的 evidence 里
有未转义的引号/换行，JSON 解析直接崩，pipeline 把整题记成 error。

这不是题目问题，是 review 输出健壮性问题。修法保持简单：review 结果只做“提取 JSON → schema 校验”；
失败时把原始 review 输出和解析错误写进 evidence/result.json，按 review failure 处理，**不自动重写、不自动重试**。
review prompt 要求用 Python `json.dumps` 生成 `review.json`，避免手写引号/换行；`json.loads` 的异常要转成
明确错误信息，不要直接冒泡成 pipeline error。`366` 由批次 retry 重跑。

### 3.4 模型/agent 行为

#### route 46 turns（7 题，已修）

- `193`、`198`（batch 05），`362/363/367/369/379`（batch 06）。
- 统一表现：`route` = `["agent_error", 46]`，旧预算 45 turns；`193` 的 rc=1、elapsed 295s，
  stderr 还有 `[claude-code:unrecognized_model]` 警告（警告不是唯一原因，46 > 45 是直接原因）。
- `6e61ef7` 把 `--route-turns` 提到 60 后，batch 09 的 30 道 route 全部完成，**0 route error**。

#### synthesis 401 turns（6 题）

这 6 题都撞到 `--max-turns 400`：synthesis 的 `status=agent_error`，root `status=failed / failure_class=synthesis_incomplete`，`result_excerpt` 为空，最后一条工具结果常见 `Exit code 137/143`。这不是 verifier 报错，而是 400-turn 上限/超时把 agent 截断；所以“失败”本身不说明题目坏，必须逐题看它在 401 时到底在做什么。

| 批次 | 任务 | turns | elapsed | 401 时在做什么 | 归类 |
|---|---|---:|---:|---|---|
| 04 | `124` libredwg | 401 | 3870s | 反复 poll build log + 在 selfcheck 脚本里用错镜像 tag | 模型写错 tag + 脚本/setsid docker 路径 |
| 04 | `166` pkp-lib | 401 | 3795s | 查 OJS `admin/contexts` 为什么 hang（`SYN_SENT` 到 172.255.54.247:80） | 题目/应用 + 外部网络 hang |
| 05 | `cve-2019-0609` chakracore | 401 | 11403s | 已跑完完整 live differential，正在做最后权限/收尾验证 | 接近完成后的过度验证 |
| 06 | `cve-2025-27513` opentelemetry | 401 | 3026s | 142 次 `true` 空转，等 apt/build | 等待策略浪费 turn |
| 06 | `osv-2023-1208` libavc | 401 | 6896s | 已跑完完整 live differential，正在 cleanup/final checks | 接近完成后的过度验证 |
| 07 | `cve-2024-0006` yugabyte | 401 | 5219s | YBA 启动失败（`DataSourceConfigurationException`），在反编译 ebean 找 DB 配置 | 应用/DB 配置难度 |

逐题证据：

**1）`124` libredwg（04，3870s）——模型写错 tag + 脚本路径问题，不是“环境整体不可用”**

- 最后 15 次调用几乎都在 selfcheck：`tail build-client.log` 共 29 次、`docker images ... grep osv2027` 共 12 次；最后在 `docker run -d --name osv771-selfcheck-client ...` 和 `docker pull` 之间反复。
- 具体错误：`workspace/delivery/environment/docker-compose.yaml:14` 写的是 `osv202771-libredwg-client:1`，但实际构建出来的 image 是 `osv2021771-libredwg-client:1`（少了一个 `1`）。`workspace/.agent-tmp/selfcheckx.log:22` 明确报 `Unable to find image 'osv202771-libredwg-client:1' locally`，`:23` 是 mirror 502；后面 `:116` 用正确 tag 才起来。
- 模型自己也在 thinking 里说：“I'm burning turns on infra flakiness”“The script-launch path is flaky on this loaded host”；它已经意识到是 `setsid`/`sg docker` 脚本路径和负载问题，但没先修 compose 的 tag。
- 交付状态：`delivery` 有 1025 个文件，`instruction.md`、`private/oracle.sh`、`private/solution.sh`、`environment/docker-compose.yaml` 都在，但 agent 没写 `verification.json`（`task.json` 由控制器在冻结前生成，这次没到那一步）；compose 的 client tag 是错的，所以即使自检过了，导出也会失败。
- 结论：**模型错误（tag 写错）+ 工具/脚本路径（setsid/sg 下 `docker run -d` 找不到镜像）**。环境有 `Command timed out after 0s` 3 次、最后 `Exit code 137`，但不是全局环境故障；主要卡点是 tag 和脚本。

**2）`166` pkp-lib（04，3795s）——OJS admin 页面出站连接 hang，模型深挖一个页面**

- 最后 15 次调用在查 OJS `admin/contexts` 为什么 hang：`SYN_SENT` 到 `172.255.54.247:80`；模型反复用 `curl`/`ps`/`/proc/net/tcp`/`grep` 追调用链。
- 统计：50 次 `curl`、82 次 `sleep`、50 次 `until`、103 次 `tail`、116 次 `grep`；`docker build` 13 次。
- 模型 thinking 原文：“I've spent enormous effort on this ONE page. DECISION: stop trying to load admin/contexts at all.” 它最后决定换策略，但已经接近 401。
- 交付状态：`delivery` 只有 1 个文件（没有 instruction/oracle/solution/compose），基本没开始打包。
- **网络实测（回答“是出网有问题吗”）**：
  - `getent hosts pkp.sfu.ca` → `172.255.54.247`；`workspace/input/src/classes/plugins/PluginGalleryDAO.inc.php:19` 是
    `PLUGIN_GALLERY_XML_URL = 'https://pkp.sfu.ca/ojs/xml/plugins.xml'`；`admin/contexts` 会触发插件/版本检查。
  - 容器 `ojs-dev-run` 里 `curl --connect-timeout 5 http://172.255.54.247:80` → **5s 超时**；
    同一容器 `curl https://github.com` → **HTTP 200 / 0.66s**。
  - 宿主机 `curl --noproxy '*' http://172.255.54.247:80` → **5s 超时**；
    但走 `proxy.pjlab.org.cn` 的 `https://pkp.sfu.ca` 能返回页面（WordPress 页）。
  - 结论：**不是全局出网坏**，是 `pkp.sfu.ca` 解析到 `172.255.54.247` 这个**直连不可达**的地址；OJS 容器没有 proxy 环境，
    插件/版本检查直连就 hang。属于“特定外部端点不可达 + 容器无代理”，不是“整台机器出不了网”。

**3）`cve-2019-0609` chakracore（05，11403s）——已经做完，最后过度验证**

- 最后 15 次调用在跑完整 live cycle：`runner rc=134`（gold）+ `oracle 0`；`benign runner rc=0` + `oracle 1`；`solution.sh` 后 `health=0` + `oracle 1`；还检查了 `healthcheck`、第二/第三种输入形状、compose down、文件权限。
- 模型 thinking：“Everything is clean”“Now let me run one final complete fresh-cycle verification with the delivery files”。它在做最后一轮收尾，不是卡在某个错误上。
- 交付状态：`delivery` 20 个文件，`instruction.md`/`oracle.sh`/`solution.sh`/`compose` 都在；agent 没写 `verification.json`（`task.json` 由控制器在冻结前生成；这次被 401 截断，没到冻结）。
- 结论：**接近完成后的过度验证**。这题如果给一个 bounded 的 finalize 阶段（比如最后 40 turns 只允许写 verification/权限检查），很可能能收；不是环境阻塞。

**4）`cve-2025-27513` opentelemetry（06，3026s）——142 次 `true` 空转等 build**

- 最后 15 次调用除了 `tail -c ... client-build.log` 就是 `true`；全轨迹 `true` 共 142 次（描述分别是 “Idle while monitors watch”“Idle awaiting monitor notification”“Await test5 monitor”）。
- 模型 thinking：“Only ~30s of wall time has passed across my idle turns (turns are fast; the perceived wait is short)… Idle.” 它以为 turn 快、等待短，实际上把 401 预算大量花在 no-op 上。
- **实测时间**：142 次 `true` 从 `synthesis/tool-calls.jsonl:213`（turn 200，2026-11-11 05:43:49.564）到 `:413`（turn 400，05:57:04.942），跨 **795.4 秒 = 13.25 分钟**；run 总耗时 3026s（05:06:44–05:57:10）。`workspace/.agent-tmp/build/client-build.log` 的 mtime 是 **06:02:43**，末尾 `client rc=0`——也就是 **build 在 agent 被 401 杀掉（05:57:10）之后约 5.5 分钟才完成**。模型说“~30s”是错的，实际是 13 分钟空转，而且没等到 build 结果。
- build 本身最终成功：`workspace/.agent-tmp/build/client-build.log` 末尾 `client rc=0`，镜像 `linux384-cve202527513-client:1` 已构建；apt 步骤在 30–40 并发下确实慢，但 build 没有失败。
- 交付状态：`delivery` 3064 个文件，但 agent 没写 `verification.json`（`task.json` 由控制器在冻结前生成，这次没到那一步）。
- 结论：**等待策略浪费 turn**，不是环境阻塞。慢 apt mirror 是环境因素，但 build 最终成功；真正的问题是模型用 `true` 空转，而不是一次 `run_in_background` + `Monitor` 等结果。142/401 ≈ 35% 的 turn 是纯 idle。

**5）`osv-2023-1208` libavc（06，6896s）——已经做完，最后 cleanup/final checks**

- 最后 15 次调用：完整 live differential：`runner rc=86` + `AddressSanitizer: heap-buffer-overflow WRITE` + `oracle 0`；`solution.sh` 后 `health=0`、`runner rc=124`（timeout，0 ASan 行）、`oracle 1`；然后 compose down、检查 proxy env、文件权限。
- 模型 thinking：“Full live-cycle verified… The complete scoring differential works. Cleanup and final checks”。它在收尾，不是卡在错误上。
- 交付状态：`delivery` 617 个文件，`instruction.md`/`oracle.sh`/`solution.sh`/`compose` 都在；agent 没写 `verification.json`（`task.json` 由控制器在冻结前生成，这次没到那一步）。
- 结论：**接近完成后的过度验证**。`fixed runner rc=124` 是它最后在查的 timeout，但 oracle 已经是 1；这题也适合 bounded finalize，而不是继续从头跑。

**6）`cve-2024-0006` yugabyte（07，5219s）——YBA 启动失败，反编译 ebean 找 DB 配置**

- 最后 15 次调用在 `javap`/`unzip`/`grep` ebean 类和 YBA 配置；错误是 `com.google.inject.CreationException: DataSourceConfigurationException: DataSource user is not set? url is [null]`。
- 统计：12 次 `javap`、13 次 `unzip`、15 次 `DataSource`、226 次 `grep`；模型 thinking：“This rabbit hole is eating time. DIFFERENT STRATEGY”。
- 交付状态：`delivery` 18 个文件，未完成。
- 结论：**应用/DB 配置难度**。YBA 需要可用的 DB/datasource；seed/启动配置没满足，应用起不来。模型选择反编译 ebean 追配置，而不是早换 DB sidecar/seed 方案；这不是“拉不到镜像/出不了网”的全局环境故障，但确实是应用配置层面的真实困难。

**汇总判断**

- 不是“6 题都遇到同一个环境故障”。更准确的分法：
  - **2 题接近完成**（chakra、libavc）：已经跑完完整 differential，最后在收尾/过度验证时被 401 截断；
  - **2 题卡在等待/脚本**（otel、libredwg）：otel 142 次 `true` 空转等 build；libredwg 自检脚本镜像 tag 写错 + `setsid`/`sg` 下 `docker run -d` 找不到镜像；
  - **2 题是题目/应用难度**（pkp、yuga）：pkp 的 OJS admin 页面出站连接 hang；yuga 的 YBA 启动因 DB/datasource 配置失败。
- 环境因素有贡献，但不是主因：otel 的 apt mirror 在 30–40 并发下慢（build 最终成功）；pkp 的外部页面连接 hang；libredwg 有 3 次 `Command timed out after 0s` 和最后 `Exit code 137`；docker 脚本在 `setsid`/`sg` 下的路径问题。没有一题是“整体环境不可用、拉不到镜像/出不了网”导致的 401。
- guard 误伤：pkp 有一次用 `..` 相对路径读自己的 background output 被 block；chakra 有 `batch-177/dev/null` 路径 typo 被 block；yuga 有 2 次 `results` 整树 scan 被 block。每次只损失 1–3 轮，不是 401 主因；但说明 guard 对“解析后位于 `/nvme/wuyida/tmp/claude-*` 的相对 `..` 路径”还需要放宽。

**建议**

1. **prompt 明确等待方式**：长 build 用一次 `run_in_background` + `Monitor`，不要用 `true`/`sleep` 空转；
   otel 的 142 次 `true` 是典型反例（实测跨 13.25 分钟）。

#### 其它 agent 异常

- `373`（`cve-2020-24753`）route 只完成 1 turn，日志在
  `results/iterate-20261110-06/batch-001/linux-373-cve-2020-24753-objsys-oocborrt/route/`。
  `stdout.jsonl:2` 的 assistant text 是一个 HTTP 200 的 HTML 页面（`<title>Claude Code –glm-5.3</title>`，
  正文是 “Model 0 (claude-fable-5-1 – baseline / control)” + “Routing task: CVE-2020-24753 … produce route.json”），
  `:3` 的 result 是 `success`、`returncode=0`、`num_turns=1`、14s；`cli-debug.log:186` 是
  `turn 1 end … stop=end_turn`；没有 `api_retry` 事件。**Claude Code 的默认重试没有生效**：
  `CLAUDE_CODE_MAX_RETRIES=15` 只重试 API/传输错误，HTTP 200 + HTML 被当成正常 completion。
  `route.json` 没生成，pipeline 记 `route_decision_missing`。这不是“transient 错误页”，更像
  proxy/router 返回了实验控制页；应在 pipeline 检测 assistant text 以 `<!DOCTYPE html>`/`<html` 开头时
  直接判 route failure（或由批次 retry 重跑），不要依赖默认重试。全批只有这 1 题出现。
- `354`（`cve-2019-25089`）、`3597`（`cve-2021-3597`）：`synthesis_blocked`，
  agent 自己报告 route 不可做；需要人工判断，不占管线 bug。

### 3.5 review 正确拒绝的题（题目质量问题，不是管线问题）

这三题是 review 起了作用，应该记录为“题目缺陷”，不要当成管线失败：

- `194`（`cve-2021-4249-file-pov`）：healthcheck 在 verifier 的非 root runner 下必然失败。
  review 证据：`docker run --user 65534:65534 ... bash /healthcheck.sh` 返回
  `runuser: may not be used by non-root users`，而 healthcheck 无条件执行
  `runuser -u nobody -- /usr/local/bin/xml-pov-run`。synthesis 只用 `docker exec -u 0` 验证过，漏了非 root 路径。
- `299`（`linux-299-cve-2021-29537-tensorflow`）：oracle 信任了提交物 stdout。
  `delivery/private/oracle.sh:41-67` grep root-only 的 gdb 日志里的
  `received signal SIG(SEGV|BUS)`、`^ORACLE_FAULT_PC_SYMBOL: `、`^#0 `，但 gdb 的 stdout 和 inferior 共享，
  提交物可以把自己的输出混进日志。review 用伪造输入（不 import tensorflow、打印三行证据、正常退出）
  复现了 `RUNNER_EXIT=0` 且 `/private/oracle.sh` 返回 0。这是 oracle 因果性缺陷。
- `375`（`cve-2021-29610-file-pov`）：目标镜像不存在。
  review 证据：`docker image inspect tf29610-client:1` 返回 `No such image`，只有 `tf29610-main:1`；
  但 `task.json` 的 `images.target` 和 compose 的 `client` 都要求该镜像，instruction 也要求在该镜像里跑 PoC。
  轨迹显示 TF ASan bazel build 只到 ~162/220 actions 就被杀，agent 自己的最后一条消息也承认
  “Next: wheel packaging, plugin + offline rebuild kit, client image...”，即 **synthesis 没做完**。
- `138`（batch 04）：`ValueError: independent review modified the submitted delivery`。
  review 不该写 delivery；这是管线的保护逻辑生效，prompt 里要再强调“review 只读”。

### 3.6 harbor trial 簇（acceptance 阶段的 trial 异常，不全是 gold 0 分）

先说明 `accept()`：它对同一道题跑 **两次** acceptance attempt（源码里的 `for attempt in (1, 2)`），
每次都是 Harbor + `pass2fail_verifier`，用 reference/gold 提交；两次 reward 都 1.0 才算 passed。
所谓 “harbor trial 簇” 是 **trial 在产出 reward 之前就抛了异常**，不是“两次 gold 验证都判 0 分”。

我把 11 个任务逐个翻了 `harbor/jobs/*/trial.log`、`exception.txt`、`verifier/evidence.json`，
并按根因分类（不是按题号猜）：

| 任务 | 失败点 | 直接证据 | 归类 / 修法 |
|---|---|---|---|
| `155` | `docker compose up --wait` 时 client unhealthy | `trial.log`: `container ...-client-1 is unhealthy` | 任务 public healthcheck；见下 |
| `371` | 同上 | `trial.log`: client unhealthy；镜像实测 `/healthcheck.sh` 不存在（`rc=127`） | 任务 public healthcheck |
| `377` | 同上 | `trial.log`: client unhealthy | 任务 public healthcheck |
| `356` | 同上 | `trial.log`: client unhealthy | 任务 public healthcheck |
| `326` | 同上 | `trial.log`: client unhealthy；镜像实测 `/healthcheck.sh` 不存在（`rc=127`） | 任务 public healthcheck |
| `327` | 同上 | `trial.log`: client unhealthy | 任务 public healthcheck |
| `355` | vulnerable health `rc=1`，`target_unhealthy` | `verifier/evidence.json`: `vulnerable.error_stage=health`, `health_rc=1` | 任务 target health |
| `167` | fixed `solution.sh` `rc=1` | `fixed.error_stage=solution`, output `[solution] FATAL: genuine patch /patch.diff missing` | solution.sh 路径；prompt/review |
| `365` | accept-1 passed；accept-2 fixed `solution_rc=56` | `curl: (56) Recv failure: Connection reset by peer`（solution 重启后立刻请求） | solution.sh 重启竞态；prompt/review |
| `192` | vulnerable oracle `rc=1` / `triggered=false` | `evidence`: oracle 1, triggered false；gold 没触发 | SVC gold miss；任务 |
| `54059` | vulnerable oracle `rc=1` / `triggered=false` | oracle `find_input` 候选没有 `/run/pass2fail/input.bin`；现在 3.1 修了 `$1` | FILE-POV 输入路径；3.1 修后 retry |

**主要发现：6 个 client unhealthy 是同一个任务侧问题，不是管线 bug。**
`155/371/377/356/326/327` 的 public `docker-compose.yaml` 都写
`healthcheck: test: ["CMD", "bash", "/healthcheck.sh"]`，但 `/healthcheck.sh` 是 **verifier 在评分时
临时挂载的 private healthcheck**，并不在 public client 镜像里。我实测了还在的两个镜像：

- `blosc2-ndlz847-client:20261111`：`/bin/bash /healthcheck.sh` → `No such file or directory`，`rc=127`。
- `linux371-cve202139255-client:1`：同样 `/healthcheck.sh` 不存在，`rc=127`。

所以 Harbor 的 `docker compose up --wait` 永远等不到 client healthy，trial 在 `_start_agent_environment`
就抛 `RuntimeError`；后面的 `Could not find /workspace/input.bin` 只是环境没起来后的次生错误，不是根因。
这是 **agent 把 private 挂载路径当成 public 镜像内容**；review 之前没有真正跑 public `up --wait`，所以没抓到。

**private vs public healthcheck 生命周期（捋一遍）**：

1. **synthesis** 写 `delivery/private/healthcheck.sh`（target 侧 normal-function 检查）。
2. **validate/export**：`pipeline/run.py:193` 要求该文件存在；`pipeline/harbor.py:610-616` 把它和 oracle/solution 一起复制到
   `profile/tests/private/healthcheck.sh`。
3. **verifier vulnerable phase（提交前）**：`pipeline/pass2fail_verifier.py:607` 跑 `health`。
   FILE-POV 把它 mount 到 `client:/healthcheck.sh`；SVC/FILE-EXPLOIT 把它 mount 到 runner 的 `/healthcheck.sh`，由
   `runner.py --health` 执行。必须 exit 0，否则 `target_unhealthy`。
4. **verifier fixed phase（solution.sh 后）**：`:637-643` 跑同一个 `patched_health`；必须 exit 0，证明 fix 没破坏正常功能。
5. **review**：review prompt 要求按 scoring 的 uid/gid 跑“最终挂载的 `/healthcheck.sh`”，所以 review 也会用到同一脚本。
6. **public `docker compose up --wait`**：**不会**跑 private `/healthcheck.sh`；它跑的是
   `delivery/environment/docker-compose.yaml` 里的 public healthcheck，必须是 public 镜像自带、无 private 材料的检查。

**结论**：private healthcheck 是 scoring 的 **normal-function gate**，有必要；6 个 client unhealthy 不是它多余，而是 agent 把
private 的 `/healthcheck.sh` 路径写进了 public compose。要减少混淆，public 侧应使用**不同的脚本名/路径**（例如
`/public_healthcheck.sh`）并 bake 进 client 镜像；private `/healthcheck.sh` 只留给 verifier。删掉 private healthcheck 会弱化验收，
也修不了 public unhealthy。

**167 / 365 是 solution.sh 自身问题**：
- `167` 的 `solution.sh` 写 `PATCH=${1:-/patch.diff}`；verifier 调它时没有传 `$1`，private patch 实际在
  `/private/patch.diff`，所以 `genuine patch /patch.diff missing`。这是路径契约问题；prompt/review 可抓，
  也可以让 verifier 把 `/private/patch.diff` 作为 `$1` 传进去（更稳，但属于新的 solution 契约）。
- `365` 第一次 accept 全绿，第二次 solution 重启服务后立刻 `curl`，遇到 `Connection reset by peer`（rc=56）；
  这是重启后没有轮询到 healthy 的竞态。prompt 已要求 bounded health poll，review 应重跑两次 fresh target。

**192 / 54059 是 gold 没触发**：
- `54059` 的 oracle 候选列表没有 `/run/pass2fail/input.bin`；现在 3.1 已让 FILE-POV oracle 收到 `$1`，
  这道应该能恢复，retry 即可。
- `192` 是 SVC real-host，gold 在 acceptance 里 `oracle_rc=1/triggered=false`；需要单独看 gold/entry，
  可能是 task-specific（agent 的 reference exploit 在新 target 上不触发），不是管线统一 bug。

**结论 / 修法**：
- **不需要为 client unhealthy 改管线代码**；这是 agent 合成的 public healthcheck 与 public 镜像不一致。
  需要补 **review prompt**：review 必须跑 public `docker compose up --wait`，任一 service unhealthy 就
  suitability failure；public healthcheck 不能引用只有 private verifier 才挂载的 `/healthcheck.sh`。
- **synthesis prompt** 已补：public healthcheck 必须自包含在 public 镜像里；`/healthcheck.sh` 只有 private
  verifier 会挂载；要 `bash /healthcheck.sh` 就把副本 bake 进 client 镜像，或改用镜像里存在的命令。
- **solution.sh**：prompt 已补“从 `/private/patch.diff` 读（或接受 `$1`），不要假设 `/patch.diff`；重启后
  轮询 healthy 再跑同一 submission；在 fresh target 测”。review 应跑两次 fresh solution。
- **54059**：3.1 已修，retry；**192**：task-specific，单独看 gold/entry。
- 之前写的“371/377 可能和 3.1 同源”不成立：它们在 environment start 就 client unhealthy，根本没到 oracle。

**修复状态（2026-11-11）**：

- **已修代码**：3.1 的 FILE-POV oracle `$1`（`oracle_argv_for()` + prompt 契约）。`54059` 可 retry，预期恢复。
- **已加 prompt/review 门禁（只防未来，不自动修已交付题）**：public healthcheck 必须自包含在 public 镜像；
  review 必须跑 `docker compose up --wait`；`solution.sh` 必须从 `/private/patch.diff`（或 `$1`）读 patch、
  重启后轮询 healthy；gold 必须在 fresh acceptance-like 环境触发。
- **未自动修**：`155/371/377/356/326/327`（client unhealthy，需重合成或修 public healthcheck/镜像）、
  `355`（target health）、`167`（solution 路径）、`365`（重启竞态）、`192`（SVC gold miss）。
- 这些题要么按 prompt/review 修复后重跑，要么按“旧题可丢弃”直接放弃；不要把它们当成“管线已修好”的证据。

### 3.7 not_suitable（12 题，正常拒绝）

`141 157 159 163 165 173`（04）、`26768`（05）、`13045 25741 40334`（06）、
`11502 36211`（07）、`298 311 315 325`（08）。这些是 route/review 判定不适合，不计入分母。

### 3.8 carry（携带题，不计入 fresh）

**carry 是什么**：`--carry-results` 把上一批已经完成 `workspace/route.json` 和完整 `workspace/delivery`、
但 review 或 harbor 没走完的旧任务目录**原样复制**到新批次，只续跑 review/harbor（或按 `carry-recovery.json`
恢复到指定阶段），**不重新跑 synthesis**。复制时会排除 `.agent-tmp` 等 scratch，并写
`carry-provenance.json`（source / instance_id / same_instance_continuation）和 `carry-recovery.json`（恢复到哪一步）。
它不是新题，也不是“重跑一遍合成”。

**为什么不计入 fresh**：fresh 是“本批新抽的 30 道题”；carry 是旧题续跑。把 carry 混进 fresh 分母会虚高或重复计算成功率。
§1.1 的“非 rejected 分母”只算 fresh；carry 单独列在 §3.8。

**本批具体状态**：
- `101/125/130/136/145/148` 是 batch 03 的 carry；按 batch 03 记录，`125/130/145` 的 retry 已 passed，
  但 batch 04 的 carry 副本当前仍是 `error/pipeline`（client unhealthy）。carry 只复制旧任务，不会改变旧结论，也不重复计数。
- `080` 是旧 harbor 状态，不是本批 fresh 结果。
- `098/119/135` 的 review 进程死亡后，`review/result.json` 一直停在 `reviewing`（stuck >90 min），
  需要单独清理/重跑，不能算“fresh 失败”或“passed”。
- 处理建议：这些题要么按 carry 单独 retry（review/harbor），要么在批次报告里标 `carry/pending`；不要混入 fresh 成功率。

## 4. 轨迹证据速查

| 任务 | 阶段 | 关键信号 | 结论 |
|---|---|---|---|
| `128/158/164/182` | acceptance | `submission input not found` / `infile cannot be read: /private/reference/input.bin` | verifier 没传 `/run/pass2fail/input.bin`；P0 |
| `331` | delivery check | `public Compose contains forbidden material: private/`，compose 第 22 行 `/vault/private/ready` | `private/` 子串误报；P0 |
| `366` | review | `review.json` line 3 col 669 | review JSON 未转义；P1 |
| `193/198/362/363/367/369/379` | route | `agent_error` turns=46，旧预算 45 | route 预算；`6e61ef7` 已修 |
| `124/166/0609/27513/1208/0006` | synthesis | turns=401，最后工具 `Exit code 137` | 模型长循环/被杀；逐题处理 |
| `373` | route | 1 turn，结果 HTML | API transient；retry |
| `138` | review | `independent review modified the submitted delivery` | review 写入 delivery；prompt 强调只读 |
| `194` | review | `runuser: may not be used by non-root users` | healthcheck 非 root 不可用；题目缺陷 |
| `299` | review | 伪造 stdout 可让 oracle 返回 0 | oracle 信任提交物日志；题目缺陷 |
| `375` | review | `No such image: tf29610-client:1` | synthesis 未完成 target 镜像；题目缺陷 |

## 5. 建议

### P0（先修，直接影响成功率）

1. **FILE-POV oracle 输入路径（已修）**：`pipeline/pass2fail_verifier.py` 新增 `oracle_argv_for()`，
   FILE-POV 自动把 `/run/pass2fail/input.bin` 作为 argv[1] 传给 `oracle.sh`；`prompts.py`/
   `doc/pipeline-prompts.md` 写死 `$1` 契约；新增 `tests/test_pass2fail_oracle_argv.py`。全量 `121 tests OK`。
   `128/158/164/182` 还没重跑，修后 harbor-only resume。
2. **`private/` 误报（已修）**：已删除 `pipeline/run.py` 的整份 compose `forbidden` 子串扫描和 volume source 子串检查；
   改为 REVIEW prompt 检查真实 bind source/凭据。已加 `/vault/private/ready` / `./fixed-assets` 回归；retry `331`。
3. **review JSON 健壮性**：只做“提取 JSON → schema 校验”；失败时把原始 review 输出和解析错误写进
   evidence/result.json，按 review failure 处理；**不自动重写、不自动重试**。review prompt 要求用 Python
   `json.dumps` 生成 `review.json`；`366` 由批次 retry 重跑。

### P1（review/prompt 质量）

4. review 必须覆盖：healthcheck 在非 root runner 下可执行（`194`）、target 镜像真实存在（`375`）、
   oracle 不能信任提交物 stdout（`299`）、review 不得写 delivery（`138`）。另外必须跑 public
   `docker compose up --wait`，任一 service unhealthy 就 suitability failure；public healthcheck
   不能引用只有 private verifier 才挂载的 `/healthcheck.sh`；`solution.sh` 必须在 fresh target 跑两次，
   从 `/private/patch.diff`（或 `$1`）读 patch，重启后轮询 healthy；gold 在 fresh acceptance-like
   环境必须触发。
5. synthesis prompt 增加“oracle 必须接受 `$1`，并搜索 `/run/pass2fail/input.bin`”（3.1 的纵深防御）
   ——**已实现**：verifier 的 `oracle_argv_for()` 会传 `/run/pass2fail/input.bin`，prompt 也写死了 `$1`。
6. harbor trial 簇已逐题定因（见 §3.6）：`155/371/377/356/326/327` 是 public client healthcheck
   引用 `/healthcheck.sh` 而镜像里没有（任务侧；review `up --wait` 可抓）；`355` 是 target health；
   `167` 是 `solution.sh` 默认 `/patch.diff`；`365` 是重启竞态；`192` 是 SVC gold miss；
   `54059` 是 FILE-POV 输入路径（3.1 已修，retry）。

### P2（稳定性/成本）

7. 保留 400 上限，不要盲目调大。
8. review stuck >90 min 的检测/重启；batch 04 的 `098/119/135` 先清理。
9. 每批结束 `docker container prune` + dangling image prune，避免根盘再次打满。
10. route 60 turns 保留；batch 09 已证明有效。

## 6. 预期

修完 P0 并只重跑受影响任务后：

- batch 04：16 → 19/24（79.2%）
- batch 05：14 → 15/20（75.0%）
- batch 07：20 → 21/28（75.0%）
- 04–07 合计：64 → **69/99（69.7%）**

06 仍受 route 旧预算影响（14/27），但那是已修代码的历史结果；新批次不应再出现 46-turn route error。
08/09 未终态，不作为成功率依据。