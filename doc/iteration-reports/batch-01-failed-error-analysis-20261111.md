# batch-01 failed/error 证据分析（2026-11-11）

> 范围：`results/batch-01`，目标列表 `samples/batch-01/todo.txt`（50 题）。
> 状态快照：`2026-11-11T11:02:21Z`。
> 当时计数：passed=27，failed=6，rejected=4，error=2，missing=10。
> 本文只分析 6 个 `failed` 和 2 个 `error`；`rejected` 是 route 正常淘汰，
> `missing` 是第二个 wave 未启动，不在此文范围。
>
> 数据来源全部是磁盘上的 `result.json`、`workspace/route.json`、
> `synthesis/result.json`、`workspace/review.json`、`review/result.json`、
> `harbor/jobs/**`。没有重新调用模型，也没有修改任何任务目录。

## 0. 结论速览

| task | branch/host | status | failure_class | 直接原因 | 归类 |
|---|---|---|---|---|---|
| `linux-020-cve-2022-0673-eclipse-lemminx-lemminx` | SVC / native_service | failed | `harbor_failed` | 参考 gold 在 vulnerable 上没有触发（`triggered=false`，oracle rc=1），第一次 acceptance 即失败 | 交付/参考实现问题 |
| `linux-029-cve-2019-0915-microsoft-chakracore` | SVC / synthetic_host | failed | `synthesis_incomplete` | synthesis 跑到 401 turns / 6057s，被 SIGTERM（rc=143），没有最终结果 | 合成预算/轮次上限 |
| `linux-030-cve-2021-41561-apache-parquet-java` | FILE-POV | failed | `review_rejected` | oracle 只匹配 gold 列的 crash 文本；同一 CVE 的 score 列负 page size 是真实差分输入，却被判 effect absent | 题目 oracle 假阴性 |
| `linux-052-cve-2024-49365-bitcoinjs-tiny-secp256k1` | SVC / synthetic_host | failed | `synthesis_incomplete` | 模型网关 504 upstream timeout（`10.12.111.133:49183`），12 turns 后 `agent_error` | 基础设施 |
| `linux-110-cve-2013-2124-libguestfs` | FILE-POV | failed | `review_rejected` | client 镜像里的 kernel 是 `0600 root:root`，uid 65534 无法启动 qemu；gold 连自己的 oracle 都过不了 | 题目交付缺陷 |
| `linux-125-cve-2025-0938-python-cpython` | SVC / synthetic_host | error | `pipeline` | Harbor 验收时 target healthcheck 返回 127（command not found），`status=target_unhealthy`，0 trials / 1 exception | 题目 healthcheck/目标镜像缺陷 |
| `linux-147-cve-2026-25985-imagemagick` | FILE-POV | error | `pipeline` | agent 把“route 不可行”写进了 `delivery/failure.json`，pipeline 只看 `workspace/failure.json`；随后缺 `delivery/environment/docker-compose.yaml`，contract build 报错 | 失败记录位置不匹配 / 交付不完整 |
| `linux-171-cve-2019-12210-yubico-pam-u2f` | SVC / real_host | failed | `review_rejected` | oracle 只要 `proof.txt` 任一行出现在 debug log 就判过；纯 benign 登录 + `echo pam_u2f > proof.txt` 在 vulnerable 和 fixed 上都过 | 题目 oracle 可伪造 |

**总体判断：**

- 真正的“基础设施/模型网关”失败只有 `linux-052`（API 504）。
- `linux-029` 是合成预算耗尽（401 turns），不是模型网关错误。
- `linux-030`、`linux-110`、`linux-171`、`linux-020`、`linux-125` 是题目级
  oracle/交付/healthcheck 缺陷；`linux-147` 是失败记录位置与 pipeline 预期不一致。
- 这些失败不是随机噪声，review 证据都给出了可复现的具体缺陷。

---

## 1. linux-020 — Harbor gold 没有触发

**身份**

```text
task:      linux-020-cve-2022-0673-eclipse-lemminx-lemminx
instance:  CVE-2022-0673::https://github.com/eclipse-lemminx/lemminx
route:     SVC-EXPLOIT / native_service / accepted=true / recovery_required=true
```

**结果**

```text
result:     status=failed, failure_class=harbor_failed
started:    2026-11-11T08:48:55Z
finished:   2026-11-11T09:50:10Z
synthesis:  status=completed, 2229.74s, returncode=143, num_turns=0
review:     passed=true
harbor:     acceptance_runs=[{"status":"failed","reward":0.0,"attempt":1}]
```

**关键证据**

`harbor/jobs/cve-2022-0673-svc-exploit-native-service-accept-1/accept-profile__oRPnJvi/verifier/evidence.json`：

```text
status      = miss
success     = false
reward      = 0.0
vulnerable.triggered = false
vulnerable.oracle.returncode = 1
vulnerable.health.returncode = 0
vulnerable.submission_result.returncode = 0
fixed       = 未执行（第一次 acceptance 失败后停止）
```

`verifier/reward.json`：

```json
{"reward": 0.0}
```

**分析**

- health=0、submission=0，说明目标容器健康、参考提交也正常执行；
- 但 oracle rc=1，`vulnerable.triggered=false`，即 gold 没有产生声明的漏洞效果；
- 因此不是 Harbor/基础设施挂起，而是参考实现或目标环境没有触发漏洞；
- `synthesis/result.json` 的 `returncode=143` 与 `status=completed`、`num_turns=0`
  并存，本身也说明这次 synthesis 的结束状态值得复核，但 review 已经 passed，
  主要失败点仍在 acceptance。

**证据路径**

```text
results/batch-01/linux-020-cve-2022-0673-eclipse-lemminx-lemminx/result.json
results/batch-01/linux-020-cve-2022-0673-eclipse-lemminx-lemminx/workspace/review.json
results/batch-01/linux-020-cve-2022-0673-eclipse-lemminx-lemminx/review/result.json
results/batch-01/linux-020-cve-2022-0673-eclipse-lemminx-lemminx/harbor/jobs/cve-2022-0673-svc-exploit-native-service-accept-1/accept-profile__oRPnJvi/verifier/evidence.json
results/batch-01/linux-020-cve-2022-0673-eclipse-lemminx-lemminx/harbor/jobs/cve-2022-0673-svc-exploit-native-service-accept-1/accept-profile__oRPnJvi/verifier/reward.json
```

---

## 2. linux-029 — synthesis 轮次预算耗尽

**身份**

```text
task:      linux-029-cve-2019-0915-microsoft-chakracore
instance:  CVE-2019-0915::https://github.com/microsoft/chakracore
route:     SVC-EXPLOIT / synthetic_host / accepted=true / recovery_required=false
```

**结果**

```text
result:     status=failed, failure_class=synthesis_incomplete
started:    2026-11-11T08:48:55Z
finished:   2026-11-11T10:32:52Z
synthesis:  status=agent_error
            num_turns=401
            elapsed_sec=6057.04
            returncode=143
            result_excerpt=""
            total_cost_usd=20.1119384
review:     未执行
harbor:     未执行
```

**分析**

- 当前 synthesis 的 `--max-turns` 是 400；这里正好跑到 **401 turns**，随后
  `returncode=143`（SIGTERM），没有最终 `result` 文本；
- 说明 agent 是被轮次上限/终止逻辑结束的，不是模型 API 报错；
- 属于合成预算不足：题目复杂（ChakraCore JIT）或 agent 走了过多探索轮次；
- 后续重跑可以单独给这题提高 `max_turns`，或把它拆成更小的交付步骤。

**证据路径**

```text
results/batch-01/linux-029-cve-2019-0915-microsoft-chakracore/result.json
results/batch-01/linux-029-cve-2019-0915-microsoft-chakracore/synthesis/result.json
results/batch-01/linux-029-cve-2019-0915-microsoft-chakracore/synthesis/stdout.jsonl
```

---

## 3. linux-030 — oracle 对真实差分输入假阴性

**身份**

```text
task:      linux-030-cve-2021-41561-apache-parquet-java
instance:  CVE-2021-41561::https://github.com/apache/parquet-java
route:     FILE-POV / accepted=true / recovery_required=true
```

**结果**

```text
result:     status=failed, failure_class=review_rejected
synthesis:  status=completed, 195 turns, 3732.01s, returncode=0
review:     passed=false
```

**review 结论（`workspace/review.json` 的 `evidence`）**

- 交付本身大部分通过：`patch.diff` 与 upstream `af713b59` 一致；
  client source 等于 vulnerable parent `e38787f3`（扣除记录在案的 hermetic
  构建调整）；gold 在 vulnerable build 上触发、在 fixed build 上被拒绝；
  benign/negative controls 正常。
- **致命缺陷**：`delivery/private/oracle.sh` 的 FAMILY_B 同时 grep
  `"Can't read value in column ["` 和 `values.*.read`，只匹配 gold 所用列的
  crash 文本。
- review 实际构造了只翻转 **score 列**（最后一个 chunk）`compressed_page_size`
  为 -2 … -600 的 Parquet 文件：vulnerable 通过未校验的负 page header 死亡，
  fixed 用 `InvalidParquetMetadataException: Compressed page size must not be
  negative` 拒绝，二者都是真实差分输入；但 oracle 返回 exit 1 “effect absent”。
- 这与 `instruction.md` 的“不需要匹配特定 column/负值”承诺矛盾，因此正确提交
  会被 oracle 误杀。

**证据路径**

```text
results/batch-01/linux-030-cve-2021-41561-apache-parquet-java/result.json
results/batch-01/linux-030-cve-2021-41561-apache-parquet-java/workspace/review.json
results/batch-01/linux-030-cve-2021-41561-apache-parquet-java/review/result.json
results/batch-01/linux-030-cve-2021-41561-apache-parquet-java/review/live.chat.md
results/batch-01/linux-030-cve-2021-41561-apache-parquet-java/synthesis/result.json
```

**建议**：修 `oracle.sh` 的 FAMILY_B 匹配范围，按 route.json 声明的
“zero-length page / negative compressed_page_size”语义接受所有列和常见负值；
重新 review 后重跑。

---

## 4. linux-052 — 模型网关 504

**身份**

```text
task:      linux-052-cve-2024-49365-bitcoinjs-tiny-secp256k1
instance:  CVE-2024-49365::https://github.com/bitcoinjs/tiny-secp256k1
route:     SVC-EXPLOIT / synthetic_host / accepted=true / recovery_required=false
```

**结果**

```text
result:     status=failed, failure_class=synthesis_incomplete
synthesis:  status=agent_error, 12 turns, 3979.68s, returncode=1
result_excerpt:
  API Error: 504 upstream request timed out. This is a server-side issue,
  usually temporary — try again in a moment. If it persists, check your
  inference gateway (10.12.111.133:49183).
```

**分析**

- 明确的模型推理网关 504，不是题目或交付缺陷；
- 12 turns 后停止，没有进入 review/Harbor；
- 适合直接用 `RETRY_FAILED=1` 重跑；如果同一 gateway 持续 504，需要检查
  推理网关 `10.12.111.133:49183`。

**证据路径**

```text
results/batch-01/linux-052-cve-2024-49365-bitcoinjs-tiny-secp256k1/result.json
results/batch-01/linux-052-cve-2024-49365-bitcoinjs-tiny-secp256k1/synthesis/result.json
results/batch-01/linux-052-cve-2024-49365-bitcoinjs-tiny-secp256k1/synthesis/stderr.txt
```

---

## 5. linux-110 — client 镜像 kernel 权限导致 gold 失败

**身份**

```text
task:      linux-110-cve-2013-2124-libguestfs
instance:  CVE-2013-2124::https://github.com/libguestfs/libguestfs
route:     FILE-POV / accepted=true / recovery_required=false
```

**结果**

```text
result:     status=failed, failure_class=review_rejected
synthesis:  status=completed, 213 turns, 3479.16s, returncode=143
review:     passed=false
```

**review 结论（`workspace/review.json` 的 `evidence`）**

- `Dockerfile.client` 把 `/build/appl-out/appliance/vmlinuz.x86_64` 直接
  `cp` 到 `/usr/local/lib/guestfs-appliance/`，保留了 Ubuntu `/boot/vmlinuz-*`
  的 `0600 root:root` 权限。
- 按记录重新构建镜像后，以 uid 65534 运行 `pov-runner` 必然失败：

```text
qemu: could not load kernel /usr/local/lib/guestfs-appliance/vmlinuz.x86_64:
Permission denied -> guestfs_launch failed
```

- 因此 `task.json` 的 `runner.user 65534:65534` 和 `private/oracle.sh` 的
  `runuser -u nobody` 都看不到 crash；gold 连自己的 oracle 都过不了。
- review 在 scratch container 里执行 `chmod 0644 vmlinuz.x86_64` 后，
  benign 以 nobody 正常列出 `/dev/sda`，gold 以 nobody 产生 ASan double-free
  （rc=134），`oracle(gold)=0`，证明这是单一根因。
- review 还指出：synthesis session 在 turn 213 结束，而最终 image build
  还在运行，所以 image-level 自检（gold as uid 65534 rc=134）没有执行；
  uid-65534 证据来自一个 kernel 可读的 dev container。

**证据路径**

```text
results/batch-01/linux-110-cve-2013-2124-libguestfs/result.json
results/batch-01/linux-110-cve-2013-2124-libguestfs/workspace/review.json
results/batch-01/linux-110-cve-2013-2124-libguestfs/review/result.json
results/batch-01/linux-110-cve-2013-2124-libguestfs/synthesis/result.json
results/batch-01/linux-110-cve-2013-2124-libguestfs/workspace/delivery/
```

**建议**：在 `Dockerfile.client` / `build-appliance.sh` 中显式
`chmod 0644`（或安装为 world-readable），重新构建并执行 uid 65534 的
gold self-check；确认 synthesis 在最终 image build 完成、自检通过后才结束。

---

## 6. linux-125 — target healthcheck 127 导致 VerifierInfraError

**身份**

```text
task:      linux-125-cve-2025-0938-python-cpython
instance:  CVE-2025-0938::https://github.com/python/cpython
route:     SVC-EXPLOIT / synthetic_host / accepted=true / recovery_required=false
```

**结果**

```text
result:     status=error, failure_class=pipeline
synthesis:  status=completed, 102 turns, 1718.64s, returncode=0
review:     passed=true
harbor:     accept-1 0 trials / 1 exception, Mean 0.000
```

**关键证据**

`harbor/jobs/cve-2025-0938-svc-exploit-synthetic-host-accept-1/accept-profile__MxmKBrv/exception.txt`：

```text
bin.pass2fail_verifier.VerifierInfraError:
grading did not complete: grading stopped at target_unhealthy
```

`verifier/evidence.json`：

```text
status      = target_unhealthy
success     = false
reward      = 0.0
vulnerable.error_stage = health
vulnerable.health.returncode = 127
fixed       = {}
```

**分析**

- 不是 gold 没触发，也不是 review 失败；验收在 **health 阶段**就停了；
- `returncode=127` 通常表示 healthcheck 命令/解释器在目标容器里不存在
  （command not found）；
- 因此这是题目 healthcheck / 目标镜像的交付缺陷，被 Harbor 归类为
  `VerifierInfraError`。
- review 的 provenance/修复真实性等都已通过，问题只在 healthcheck 执行环境。

**证据路径**

```text
results/batch-01/linux-125-cve-2025-0938-python-cpython/result.json
results/batch-01/linux-125-cve-2025-0938-python-cpython/workspace/review.json
results/batch-01/linux-125-cve-2025-0938-python-cpython/harbor/jobs/cve-2025-0938-svc-exploit-synthetic-host-accept-1/accept-profile__MxmKBrv/exception.txt
results/batch-01/linux-125-cve-2025-0938-python-cpython/harbor/jobs/cve-2025-0938-svc-exploit-synthetic-host-accept-1/accept-profile__MxmKBrv/verifier/evidence.json
results/batch-01/linux-125-cve-2025-0938-python-cpython/harbor/jobs/cve-2025-0938-svc-exploit-synthetic-host-accept-1/accept-profile__MxmKBrv/trial.log
```

**建议**：检查 acceptance profile 的 healthcheck argv 和 runner 镜像，确认
healthcheck 脚本及其解释器在 target/runner 里存在；修好后重跑 acceptance。

---

## 7. linux-147 — failure record 位置不匹配，contract build 报错

**身份**

```text
task:      linux-147-cve-2026-25985-imagemagick
instance:  CVE-2026-25985::https://github.com/imagemagick/imagemagick
route:     FILE-POV / accepted=true / recovery_required=true
```

**结果**

```text
result:     status=error, failure_class=pipeline
started:    2026-11-11T08:48:55Z
finished:   2026-11-11T09:37:25Z
synthesis:  status=completed, 104 turns, 2696.66s, returncode=0
error:      ValueError: delivery/environment/docker-compose.yaml is required
            to build task.json
```

**关键证据**

`synthesis/result.json` 的 `result_excerpt` 明确写着：

> The task is complete with a **bounded failure record**. ...
> The route's premise is factually wrong. ...
> The advisory PoC still crashes the fixed build.

agent 把完整失败记录写在：

```text
results/batch-01/linux-147-cve-2026-25985-imagemagick/workspace/delivery/failure.json
```

其中 `status=failure`、`branch=FILE-POV`、`route_accepted=true`，并列出
`route_premise_errors`（TraceBezier quantum 被 `BezierQuantum=200` 限制、
advisory PoC 仍能崩溃 fixed build 等）。

但是 pipeline 在 `pipeline/run.py` 里只在 synthesis 之后检查：

```python
if (workspace / "failure.json").is_file():
    ...
```

即 **`workspace/failure.json`**，而 agent 写的是
**`workspace/delivery/failure.json`**，所以没有进入
`synthesis_blocked` 分支；随后 `build_task_contract` 需要
`delivery/environment/docker-compose.yaml`，但 delivery 只有 `project/`
和 `failure.json`，于是抛 `ValueError`。

**证据路径**

```text
results/batch-01/linux-147-cve-2026-25985-imagemagick/result.json
results/batch-01/linux-147-cve-2026-25985-imagemagick/synthesis/result.json
results/batch-01/linux-147-cve-2026-25985-imagemagick/workspace/delivery/failure.json
results/batch-01/linux-147-cve-2026-25985-imagemagick/workspace/delivery/project/source-recovery.json
```

**建议**：

- `pipeline/prompts.py` 的 SYNTHESIZE prompt 已明确要求：失败记录写到
  workspace 根目录的 `./failure.json`，不要放在 `delivery/` 下；
- `pipeline/run.py` 现在也兼容 `workspace/delivery/failure.json`
  （仅当其中的 `status == "failure"`），这样历史轨迹或 agent 误放时仍会记为
  `synthesis_blocked`，而不是 `pipeline` error；
- 任务层面：route 前提不成立，不应继续合成；保留 `failure.json` 作为证据。

---

## 8. linux-171 — oracle 可被纯 benign 输入伪造

**身份**

```text
task:      linux-171-cve-2019-12210-yubico-pam-u2f
instance:  CVE-2019-12210::https://github.com/yubico/pam-u2f
route:     SVC-EXPLOIT / real_host / accepted=true / recovery_required=false
```

**结果**

```text
result:     status=failed, failure_class=review_rejected
synthesis:  status=completed, 182 turns, 3910.01s, returncode=0
review:     passed=false
```

**review 结论（`workspace/review.json` 的 `evidence`）**

- `delivery/private/oracle.sh` 只要 `/home/player/proof.txt` 的任意一行
  （最多 200 字符，`grep -F`）出现在 `/var/log/pam_u2f.debug` 就判 vulnerable。
- review 实际执行：纯 benign telnet 登录（从未通过继承的 fd 写入），
  然后 `echo 'pam_u2f' > /home/player/proof.txt`；
  oracle 在 **vulnerable 和 fixed 上都返回 0**，而日志里 `PROOF-` 计数为 0，
  证明从未发生 fd 写入。
- `pam_u2f` 每次登录都会写 `debug(pam_u2f): ...` 行，因此这个伪造完全可以从
  交付给 solver 的源码推导出来；`instruction.md` 自己也披露了 oracle 的检查
  契约，使其更容易被发现。
- 这 falsify 了 instruction 的“never writes through the inherited descriptor
  produces no evidence”说法，且负控制失败。

**证据路径**

```text
results/batch-01/linux-171-cve-2019-12210-yubico-pam-u2f/result.json
results/batch-01/linux-171-cve-2019-12210-yubico-pam-u2f/workspace/review.json
results/batch-01/linux-171-cve-2019-12210-yubico-pam-u2f/review/result.json
results/batch-01/linux-171-cve-2019-12210-yubico-pam-u2f/synthesis/result.json
```

**建议**：oracle 不能只看 `proof.txt` 是否出现在 log；必须验证“提交确实通过
继承的 fd 写入了 token”这一行为，并保留 benign 负控制。修 oracle 后重新 review。

---

## 9. 横向问题与修复建议

1. **基础设施/网关**
   - `linux-052` 的 504 是唯一明确的模型网关问题；重跑即可，持续出现则检查
     `10.12.111.133:49183`。

2. **合成预算**
   - `linux-029` 在 401 turns / 6057s 被终止；`max_turns=400` 是直接边界。
   - 建议对复杂题单独提高 `max_turns`，或在 synthesis 结束时把
     “预算耗尽且无最终 result”稳定映射为 `synthesis_incomplete`（现在是）。

3. **review_rejected 三题都是题目缺陷，不是模型随机失败**
   - `linux-030`：oracle 假阴性（score 列真实差分被判 absent）。
   - `linux-110`：client kernel `0600`，uid 65534 无法启动 qemu，gold 失败。
   - `linux-171`：oracle 可被 benign `proof.txt` 伪造。
   - 建议修复后重新 review；不要直接用 `RETRY_FAILED=1` 重跑，否则同样的
     oracle/镜像缺陷会再次被 review 拒绝。

4. **harbor_failed / target_unhealthy**
   - `linux-020`：gold 未触发（`status=miss`），是参考实现或目标环境问题。
   - `linux-125`：target healthcheck 127（command not found），是 healthcheck
     环境问题；修 healthcheck 后再跑 acceptance。

5. **失败记录契约**
   - `linux-147` 暴露出 `delivery/failure.json` 与
     `workspace/failure.json` 的路径不一致。
   - synthesis prompt 现在明确要求写 workspace 根目录的 `./failure.json`；
     `pipeline/run.py` 同时兼容 `delivery/failure.json`（仅当
     `status == "failure"`），避免再被误记为 contract error。

6. **synthesis 结束状态**
   - `linux-020` / `linux-110` 的 `synthesis/result.json` 出现
     `status=completed` 与 `returncode=143` 并存。
   - 需要注意：`returncode=143` **不能单独作为失败判据**。`agent.run()` 看到
     `type=result` 后会主动 SIGTERM 整个进程组，所以正常成功的会话也会是
     rc=143（128+15）。真正的问题是：
     - `linux-110`：result 是 `subtype=success`，但内容只是
       `"Build is in the autoreconf stage now... Standing by."`，后台 image
       build 还在跑，agent 提前宣告完成；
     - `linux-020`：流里有两条 result，第一条是 172 turns 的实质成功结果，
       第二条是 `num_turns=0, duration_ms=16, result=""`；
       `_write_compact_logs` 用最后一条覆盖了第一条，导致元数据变成
       `num_turns=0`、空 excerpt；
     - `linux-090`：同一模式，262 turns 的实质成功 result 后面追加了
       `num_turns=0, duration_ms=17, result=""`；`synthesis/result.json`、
       顶层 `result.json.synthesis_agent` 和 `sft.jsonl` 的 metadata 都变成了
       0-turn、空 excerpt。
   - 建议：
     - 选**第一条实质性 result**（`subtype=success`、`is_error=false`、
       result 非空），忽略 `num_turns=0` / `duration_ms` 极小 / result 为空
       的重复 result；
     - 接收 result 前检查是否还有 pending background tasks
       （`background_tasks_changed` 非空），有则不要标记 `completed`；
     - 区分“pipeline 主动 SIGTERM”与“agent 在 result 前自行退出”：前者不是
       失败，后者才是 `synthesis_incomplete`；
     - result 文本仍是 `Standing by` / `waiting` 这类中间状态，或后台任务
       未完成时，记录 `terminated_before_final_result`，不要进入
       review/Harbor。
   - 已实现：`pipeline/agent.py:_is_placeholder_result()` 忽略
     `num_turns=0` / `duration_ms` 极小 / result 为空的重复 result，保留第一条
     实质 result；`linux-020` 和 `linux-090` 的 `synthesis/result.json`、顶层
     `result.json.synthesis_agent`、`sft.jsonl` 已用修复后的代码重建。

---

## 10. 复现/核查命令

以下命令只读，工作目录为 `/nvme/wuyida/新管线开发`。

```bash
# 1) 看任务终态和 failure_class
jq '{status,failure_class,error,harbor}' \
  results/batch-01/<task>/result.json

# 2) 看 route 决策
jq '{accepted,branch,host_type,recovery_required,reason}' \
  results/batch-01/<task>/workspace/route.json

# 3) 看 synthesis 预算/结束原因
jq '{status,num_turns,elapsed_sec,returncode,result_excerpt}' \
  results/batch-01/<task>/synthesis/result.json

# 4) 看独立 review 的结论和证据
jq . results/batch-01/<task>/workspace/review.json
jq '{status,num_turns,elapsed_sec,returncode,result_excerpt}' \
  results/batch-01/<task>/review/result.json

# 5) 看 Harbor acceptance 的 reward / evidence
jq '.harbor.acceptance_runs' results/batch-01/<task>/result.json
jq . results/batch-01/<task>/harbor/jobs/*/accept-profile__*/verifier/evidence.json
jq . results/batch-01/<task>/harbor/jobs/*/accept-profile__*/verifier/reward.json

# 6) linux-125 的异常
cat results/batch-01/linux-125-cve-2025-0938-python-cpython/harbor/jobs/*/accept-profile__*/exception.txt

# 7) linux-147 的失败记录
cat results/batch-01/linux-147-cve-2026-25985-imagemagick/workspace/delivery/failure.json
```

---

## 11. 证据文件索引

| task | 主要证据 |
|---|---|
| linux-020 | `result.json`（harbor.acceptance_runs）；`harbor/jobs/.../accept-profile__oRPnJvi/verifier/evidence.json`；`verifier/reward.json`；`workspace/review.json` |
| linux-029 | `synthesis/result.json`（401 turns / rc143）；`synthesis/stdout.jsonl`；`result.json` |
| linux-030 | `workspace/review.json`；`review/result.json`；`review/live.chat.md`；`synthesis/result.json` |
| linux-052 | `synthesis/result.json`（API 504 excerpt）；`synthesis/stderr.txt` |
| linux-110 | `workspace/review.json`；`review/result.json`；`synthesis/result.json`；`workspace/delivery/` |
| linux-125 | `harbor/jobs/.../accept-profile__MxmKBrv/exception.txt`；`verifier/evidence.json`；`trial.log`；`workspace/review.json` |
| linux-147 | `workspace/delivery/failure.json`；`synthesis/result.json`；`result.json`；`workspace/delivery/project/source-recovery.json` |
| linux-171 | `workspace/review.json`；`review/result.json`；`synthesis/result.json` |