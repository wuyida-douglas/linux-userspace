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

## 2. 管线修复清单

| 提交 | 问题 | 修法 | 验证 |
|---|---|---|---|
| `663d81d` | `--settings` 用相对路径，CLI 在 workspace 下找不到 `agent-guard.json`，batch 02 的 30 个 route 全挂 | `agent.py` 里 workspace/output/network/debug/settings 全部 `.resolve()` | pilot route 343s/34 turns 成功，batch 03 起 route 恢复 |
| `c4ee0f6` / `6fe0540` / `9e8f6b5` / `4f4ae47` | acceptance 的 reference 没被 Harbor 收集；文件 bind 的 target 被 Docker 建空目录；最终根因是 bind source 相对路径 | profile/accept-profile/reference 全 `.resolve()`；reference 复制到 `accept-profile/tests/private/reference`；挂目录 `/opt/reference`；no-op agent `cp` 到 `/workspace` | batch 04 的 16 道 fresh 全部新 acceptance 2×1.0 |
| `47058bb` | `TimeoutExpired.stdout` 是 bytes，`str + bytes` 抛 `TypeError`，187/190 验收失败 | `_as_text()` 统一 bytes/str | 187/190 修复后 2×1.0 |
| `d170916` | carry 复制 `.agent-tmp/root/vuln` 权限拒绝 | `copytree(ignore=...)` 排除 `.agent-tmp`、`.agent-config`、`harbor` 等 | batch 04 carry 正常 |
| `6e61ef7` | route 45 turns 不够（46 turns `agent_error`），accept 3 turns 也不够 | `--route-turns 60`、`--accept-turns 8` | batch 09 route 30/30 无 route error |
| `715cf20` | review/synthesis 没把“可做性、自洽、oracle 归因”写清楚 | prompts 增加 solvability/self-consistency/oracle 因果/负控 | 后续 review 抓到 194/299/375 |
| `39b49de` | batch 04 报告 | — | — |
| 运维 | 根盘 98% full，镜像 load `no space left on device` | `docker container prune`（57.45GB）、image prune、builder prune | 根盘恢复数百 GB |

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
和交付目录相对引用（`private/` 开头、`../private`、`$PWD/private`），允许 `/vault/...` 这类容器内绝对路径。
加一条回归：healthcheck 命令里出现 `/vault/private/ready` 不应被拒。修复后 retry `331`。

### 3.3 P1：review 输出不是合法 JSON（366）

`366`（`cve-2020-7781-svc-exploit-synthetic-host`）报：

```text
JSONDecodeError: Expecting ',' delimiter: line 3 column 669 (char 688)
```

坏文件是 `workspace/review.json`（`task.json` 本身是好的）。review agent 写出的 evidence 里
有未转义的引号/换行，JSON 解析直接崩，pipeline 把整题记成 error。

这不是题目问题，是 review 输出健壮性问题。修法：review 结果用“提取 JSON → schema 校验 →
失败则让 review 重写一次/带错误信息重试”的流程；至少不要让 `json.loads` 直接冒泡成 pipeline error。
retry `366` 即可。

### 3.4 模型/agent 行为

#### route 46 turns（7 题，已修）

- `193`、`198`（batch 05），`362/363/367/369/379`（batch 06）。
- 统一表现：`route` = `["agent_error", 46]`，旧预算 45 turns；`193` 的 rc=1、elapsed 295s，
  stderr 还有 `[claude-code:unrecognized_model]` 警告（警告不是唯一原因，46 > 45 是直接原因）。
- `6e61ef7` 把 `--route-turns` 提到 60 后，batch 09 的 30 道 route 全部完成，**0 route error**。

#### synthesis 401 turns（6 题）

| 批次 | 任务 | turns | elapsed |
|---|---|---:|---:|
| 04 | `124` libredwg | 401 | 3870s |
| 04 | `166` pkp-lib | 401 | 3795s |
| 05 | `cve-2019-0609` | 401 | 11403s |
| 06 | `cve-2025-27513` | 401 | 3026s |
| 06 | `osv-2023-1208` | 401 | 6896s |
| 07 | `cve-2024-0006` | 401 | 5219s |

最后一条工具结果多为 `Exit code 137`（进程被杀/OOM），不是 verifier 报错。
这是模型在复杂题目里长时间打转，撞到 400-turn 上限；属于模型/题目难度，不是管线 bug。
可以加“连续 N 轮没有新文件/没有进度就提前停”的止损，但不要简单把 400 再调大（会掩盖卡死）。
这 6 题需要逐题看轨迹决定是人工接手还是丢弃。

#### 其它 agent 异常

- `373`（`cve-2020-24753`）route 只完成 1 turn，结果摘要是
  `<!DOCTYPE html>...Claude Code –glm-5.3`，API 返回了 HTML 错误页；transient，retry 即可。
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

### 3.6 harbor trial 簇（尚未逐题定因）

这些题报 `RuntimeError: Harbor trial failed`，dump 里没有足够 evidence，先不判“题目坏”：

- `155`：acceptance client healthcheck unhealthy（batch 04 报告）。
- `167`：evidence 是 `infra_error`；`vulnerable.oracle` 返回 0、`triggered=True`、
  输出 `effect PRESENT`，但 patched 阶段缺失，trial 没走完。
- `365/371/377`（batch 06）、`355/356`（batch 07）、`326/327`（batch 08）、
  `192/25533`（batch 05）、`54059`（batch 07）。
- 其中 `371/377/326/327/54059` 是 FILE-POV，**可能和 3.1 的输入路径同源**；修完 3.1 后优先 retry 它们。
- `355/356/326/327` 此前出现过 client unhealthy / compose exception；需要看各自 `harbor/jobs/*/job.log`
  的 `up`/`health`/`private_upload` 阶段，不要直接归为模型问题。

### 3.7 not_suitable（12 题，正常拒绝）

`141 157 159 163 165 173`（04）、`26768`（05）、`13045 25741 40334`（06）、
`11502 36211`（07）、`298 311 315 325`（08）。这些是 route/review 判定不适合，不计入分母。

### 3.8 carry（不计入 fresh）

`101/125/130/136/145/148` 是 batch 03 carry；`125/130/145` 已在 batch 03 retry passed；
`101/136/148` 仍 client unhealthy；`080` 旧 harbor 状态；`098/119/135` review 进程死亡后
`review/result.json` 一直 running（stuck >90 min），需要单独清理，不要重复计入成功率。

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

1. **FILE-POV oracle 输入路径**：`pipeline/pass2fail_verifier.py` 在 `:680` 调 oracle 时，把
   `destination`（`/run/pass2fail/input.bin`）作为 argv[1] 传进去；同时要求 FILE-POV 的 `oracle.sh`
   必须能处理 `$1`。加回归测试；retry `128/158/164/182`。
2. **`private/` 误报**：`pipeline/run.py:226-230` 不要扫整份 compose；只查 bind source 和交付目录相对引用。
   加 `/vault/private/ready` 回归；retry `331`。
3. **review JSON 健壮性**：解析失败可重试/带错误回给 review，不要把 `JSONDecodeError` 变成 pipeline error；
   retry `366`。

### P1（review/prompt 质量）

4. review 必须覆盖：healthcheck 在非 root runner 下可执行（`194`）、target 镜像真实存在（`375`）、
   oracle 不能信任提交物 stdout（`299`）、review 不得写 delivery（`138`）。
5. synthesis prompt 增加“oracle 必须接受 `$1`，并搜索 `/run/pass2fail/input.bin`”，作为 3.1 的纵深防御
   （即使 verifier 以后又忘了传参，题目自己也能找到）。
6. 对 `155/167/365/371/377/355/356/326/327/192/25533/54059` 逐题看 `harbor/jobs/*/job.log` 的
   `up`/`health`/`private_upload` 阶段；FILE-POV 的先按 3.1 retry，SVC 的分开看 health/oracle。

### P2（稳定性/成本）

7. synthesis 401 加“无进度提前停”，保留 400 上限；不要盲目调大。
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