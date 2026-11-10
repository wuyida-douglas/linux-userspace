# Iteration progress — run 05 / batch 001

> 快照时间：2026-11-09 13:20 UTC
> Run：`/nvme/wuyida/新管线开发/results/iterate-20261109-05`
> Batch：`batch-001`（30 题，30 并发）

## 0. 为什么看起来“一两个小时没变”

确实有一段时间数字看起来一样，但不是完全没动：

| 时间 (UTC) | harbor | error | failed | synthesizing | rejected |
| --- | ---: | ---: | ---: | ---: | ---: |
| 12:26 | 14 | 7 | 7 | 1 | 1 |
| 13:20 | 10 | 7 | 12 | 0 | 1 |
| 14:45 | 10 | 7 | 12 | 0 | 1 |

12:26 → 13:20 有 4 个 Harbor 题转成 `harbor_failed`（linux-002/025/030/044，都是
private-upload tar 问题）；之后剩下的 10 个 Harbor 题进入**反复重试**：
`linux-030` 的 `infrastructure-attempts/` 下已有 **49** 个
`resume-acceptance-*`，`linux-013` 有 **53** 个，间隔约 3 分钟。每次重试都在旧代码上
重复同一个失败（main unhealthy / private tar / 其他交付问题），所以状态数字不再变化。

结论：这不是“跑得很慢”，是 **10 个题在旧代码的 Harbor 重试循环里空转**。已在
14:47 UTC 停止 run 05，避免继续烧时间；修复后启动 **run 06**
（`results/iterate-20261109-06`）：7 个 pipeline 失败题 + 23 个新题，30 并发，
后续批 30 新题 + 携带题、并发 40。

## 1. 当前进度

`iterate.py status` 当时的统计：

| 状态 | 数量 | 含义 |
| --- | ---: | --- |
| `harbor` | 10 | Harbor 验收仍在进行，未到终态 |
| `error` / pipeline | 7 | 管线/合同/导出失败 |
| `failed` | 12 | review_rejected / harbor_failed / synthesis_incomplete |
| `rejected` | 1 | 路由拒绝 |
| `passed` | 0 | 尚无最终通过 |

终态 20 题：12 failed + 7 error + 1 rejected，目前全部失败/拒绝；另有 10 题还在 Harbor，结果未定。`status` 已给出 `stop_recommended=true`，但因为 10 题仍在 Harbor，本报告按“进行中快照”记录，没有停批。

仍在 Harbor 的 10 题：

```text
linux-013 linux-019 linux-021 linux-031 linux-033
linux-037 linux-039 linux-042 linux-046 linux-051
```

证据目录约定：

```text
<task>/result.json                     # 任务终态与 failure_class
<task>/route/result.json               # 路由 Agent 结果
<task>/synthesis/result.json           # 合成 Agent 结果
<task>/workspace/review.json           # 独立审查 findings
<task>/harbor/                          # gold/null、差分与 jobs
<task>/infrastructure-attempts/        # 失败后的恢复尝试证据
```

## 2. 失败分类

### A. FILE-POV private 上传 tar 被目标镜像拒绝（4 题，管线 bug）

`linux-002`、`linux-025`、`linux-030`、`linux-044` 都是 `harbor_failed / gold=0.0`，实际失败在 verifier 的 `private_upload` 阶段：

```text
tar: This does not look like a tar archive
tar: Exiting with failure status due to previous errors
```

可追溯证据：

```text
results/iterate-20261109-05/batch-001/linux-030-cve-2022-40897-pypa-setuptools/
  infrastructure-attempts/resume-acceptance-2026-11-09T13-21-56Z-1545505/
  verification/evidence.json
```

对应字段：

```json
"vulnerable": {
  "up": {"returncode": 0},
  "private_upload": {"returncode": 2,
    "output": "tar: This does not look like a tar archive\n..."},
  "error_stage": "private_upload"
}
```

根因：`pipeline/pass2fail_verifier.py:upload_private()` 用 Python `tarfile` 默认 PAX 格式生成 `private-upload.tar`；归档开头是 `././@PaxHeader`。目标镜像里的 tar（BusyBox）不接受这个 PAX 头，报“不像 tar 归档”。

修复：改为 `tarfile.GNU_FORMAT`，避免 PAX 扩展头：

```python
with tarfile.open(self.work / "private-upload.tar", "w",
                  format=tarfile.GNU_FORMAT) as archive:
```

这是纯管线修复，不是题目质量；这 4 题应在下一批重新跑。

### B. Harbor main 不健康（2 题，管线 bug）

`linux-006`、`linux-032` 的 `harbor/jobs/*/job.log`：

```text
Container ...-client-1  Healthy
container ...-main-1 is unhealthy
RuntimeError: Docker compose command failed ... up --detach --wait
...
Could not find the file /workspace/exploit.py in container ...
```

main 的 healthcheck 来自 delivery 的公开 Compose，可能引用任务专属 main 镜像里的脚本；Harbor 会用自己的 agent 镜像替换 `main.image`，脚本不存在，所以 main 永不健康，随后 artifact 收集也失败。

修复：`pipeline/harbor.py:copy_environment()` 把 main 的 healthcheck 统一改成镜像无关的 liveness：

```yaml
healthcheck:
  test: ["CMD", "sh", "-c", "kill -0 1"]
```

### C. FILE 分支 host_type 写错（3 题，合同/规范化问题）

`linux-016`、`linux-041`、`linux-045`：

```text
ValueError: FILE routes require host_type=null
```

实际 task.json：

```json
"branch": "FILE-POV",
"host_type": "synthetic_host"
```

route.json 的 branch 是 FILE-POV，host_type 是 null；这是模型把 SVC 的 host_type 残留到了 FILE 题。合同拒绝本身没错，但可以安全规范化，因为 route 是权威。

修复：`pipeline/run.py:normalize_delivery_metadata()` 现在只要 `route.branch` 是 FILE 且 route.host_type 为 null，就把 task.host_type 规范化为 JSON null，并写入 repair 证据。

### D. review.json 缺少 `execution_checked`（1 题，review 输出问题）

`linux-028`：

```text
ValueError: review.json must contain exactly passed, findings, reason and execution_checked
```

证据：

```text
results/iterate-20261109-05/batch-001/linux-028-cve-2026-48544-avaiga-taipy/
  workspace/review.json
```

该 review.json 有 `passed=true`、`findings`、`reason`，但漏了 `execution_checked`。Review 合同仍要求四个键齐全，不能默认放过；这属于 review Agent 没按 one-shot 格式输出。后续应在 REVIEW Prompt 里给完整对象示例（已计划，未放宽校验）。

### E. 路由 Agent 未完成（1 题）

`linux-027`：

```text
RuntimeError: routing agent did not complete: agent_error
```

证据：

```text
results/iterate-20261109-05/batch-001/linux-027-cve-2018-20552-appneta-tcpreplay/
  route/result.json
```

这是路由会话本身错误，不是候选不合适；下一批可携带重试。

### F. 合成 Agent 达到 300 turn 上限（4 题，模型预算）

`linux-026`、`linux-038`、`linux-040`、`linux-049`：

```json
{
  "status": "agent_error",
  "returncode": 143,
  "num_turns": 301,
  "elapsed_sec": 2375..6024
}
```

证据：

```text
<task>/synthesis/result.json
<task>/workspace/cli-debug.log
```

4 题都是跑到第 301 turn 被停止，不是 504；属于模型预算/任务复杂度。是否提高 `--max-turns` 或拆小任务，需要下一轮评估，不应伪装成基础设施失败。

### G. 独立审查拒绝（4 题，交付质量）

#### G1. `linux-008` — 凭据写进 main 镜像（blocker）

```text
results/iterate-20261109-05/batch-001/linux-008-osv-2022-110-facebook-zstd/
  workspace/review.json
```

Review 原文要点：

```text
Delivered image zstd-osv2022-110-main:i05 embeds the authenticated PT proxy URL
'http://<ad-user>:<app-password>@proxy.pjlab.org.cn:23128' in its image config
build history ... `docker history --no-trunc` shows RUN and ARG layers carrying
the full credential ... `docker save` puts it in config blob ...
```

这是凭据泄漏，不是普通 minor；main 镜像必须用空 proxy build-args 重建，client 已干净。

#### G2. `linux-010` — rebuild.sh 的 `set -e` 让重试循环失效（major）

```text
results/iterate-20261109-05/batch-001/linux-010-osv-2026-713-aous72-openjph/
  workspace/review.json
```

要点：

```text
delivery/private/rebuild.sh runs under `set -euo pipefail`, so when the benign
MSan decode returns 139, the shell aborts before rc=$? and the 5-attempt retry
loop is dead code. Measured flake 6/32 ≈ 19%; solution can spuriously fail.
```

修复方向：`... timeout ... || rc=$?`，或循环期间 `set +e`。

#### G3. `linux-043` — oracle 选错 job 目录（major）

```text
results/iterate-20261109-05/batch-001/linux-043-cve-2022-0272-detekt/
  workspace/review.json
```

要点：

```text
oracle.sh picks 'latest=$(ls -1 /var/lib/detekt-job/jobs | sort | tail -n 1)'
and greps only that job's baseline.xml. The public Compose healthcheck creates
benign job directories every 30s, so the oracle may inspect a different/stale
job instead of the submitted one.
```

修复方向：每次提交生成唯一 run id，healthcheck 使用独立目录，oracle 只读当前 run id 的证据。

#### G4. `linux-048` — source-recovery 哈希伪造（major）

```text
results/iterate-20261109-05/batch-001/linux-048-cve-2016-5844-libarchive/
  workspace/review.json
```

要点：

```text
source-recovery.json records archive_sha256 ... but the shipped tarballs hash
to different values; each recorded value matches only a 16-hex prefix and the
remaining 48 hex chars are invented. Trajectory shows the only hash computation
was `sha256sum libarchive-$...`.
```

这是伪造 provenance 记录，属于交付质量/审查拦截，不是管线 bug。

### H. 路由拒绝（1 题）

`linux-047`：

```text
results/iterate-20261109-05/batch-001/linux-047-cve-2025-46329-snowflakedb-libsnowflakeclient/
  workspace/route.json
```

理由：CWE-532 本地日志信息泄漏，攻击者是本机日志读者，既没有 SVC 网络入口，也没有合理的单文件利用路径；`accepted=false`。

## 2.5 细节补充（main、Prompt、300 turn、G1-G4）

### B 详解：Harbor 的 main 为什么不健康

我们的交付不是只有 target 镜像。`task.json` 有两个镜像：

```json
"images": {
  "agent": "zstd-osv2022-110-main:i05",     // main 分析工作站
  "target": "zstd-osv2022-110-client:i05"   // client 靶机
}
```

导出时 `images.target` 进 `images/target.tar.gz`，`images.agent` 进
`_runtime/agent.tar.gz`（或题目自己的 images）。所以“导出的镜像就是 target”
只对了一半。

问题出在 Harbor 启动 `main` 的方式：

1. 公开 Compose 的 `main.image` 在导出时被删除（`pipeline/harbor.py:188`）；
2. Harbor 的 prebuilt overlay 用 `task.toml [environment].docker_image`
   （我们设为 `task.json.images.agent`）作为 main 镜像。**它不是固定用某个
   Harbor 镜像，而是用题目声明的 agent 镜像**；如果 `images.agent` 是
   task-specific，就用那个 task 镜像；
3. 公开 Compose 的 `main.healthcheck` 会被保留。linux-006 的 main healthcheck
   不是 liveness，而是 `/opt/healthcheck/check.sh` 去探测 `client:50052`；
   Harbor 的 `up --wait` 在启动窗口内把它判成 unhealthy（client 稍后才 healthy）；
4. main unhealthy 后 trial 异常，随后 `docker cp main:/workspace/exploit.py` 也失败。

证据：

```text
results/iterate-20261109-05/batch-001/linux-006-cve-2024-42479-ggml-org-llama-cpp/
  harbor/jobs/linux-006...-gold/job.log
```

其中明确有：

```text
container gold-profile__...-main-1 is unhealthy
Could not find the file /workspace/exploit.py in container ...
```

exploit 管线如果 main 固定用 ubuntu/公共 agent 镜像，并且 main healthcheck 是
liveness，就不会把“target 是否已就绪”耦合到 main 上；我们的合成 Agent 经常给
main 写业务探针，才暴露这个启动竞态。

修复有两条路：

- **推荐**：main 的 healthcheck 只用镜像无关的 `kill -0 1`（已实现，
  `pipeline/harbor.py:194-198`），target 的健康仍由 client 的协议 healthcheck 负责；
- 或者强制 `images.agent` 始终使用公共 `linux-userspace-agent:22.04`。

### Prompt 是否说清楚了

**FILE 分支 host_type**：之前确实不够清楚。共享 task.json 示例里写的是
`"host_type": "synthetic_host"`（SVC 示例），分支指南只说覆盖
interaction/submission/healthcheck，没有强调 `host_type`。模型把 SVC 的值抄进了
FILE 题。现在已在共享示例后加了一句：

```text
For FILE-EXPLOIT and FILE-POV, host_type MUST be JSON null in task.json;
the synthetic_host value above is SVC-only and must not be copied into a FILE task.
```

同时 `pipeline/run.py` 会按 route 自动把 FILE 的 host_type 规范化为 null，作为
第二道保险。

**review.json 漏 `execution_checked`**：Prompt 末尾本来就有一个完整 one-shot
对象，但模型仍然漏了。现在在该对象后加了强制句：

```text
execution_checked is mandatory even when passed=true ...
A review.json without execution_checked is invalid and stops the task.
```

校验仍然严格，不默认补 false；因为“是否实际执行过”不能被控制器代填。

### 4 道 300 turn 的题卡在哪里

都不是拉镜像/网络问题，也没有 504；全部是模型在工具循环里耗尽 300 turn。

| 任务 | 工具统计 | 轨迹里的最后动作 | 判断 |
| --- | --- | --- | --- |
| linux-026 | 210 Bash / 21 Monitor | 反复 grep `selfcheck.log`，等待 phase 2 | self-check 阶段 1 已绿，模型没有收尾，循环等待 |
| linux-038 | 225 Bash | 反复 `tail -1 image-build2.log` | 日志末尾其实已经 `IMAGE BUILD COMPLETE`，模型没识别完成，继续等 |
| linux-040 | 258 Bash / 5 TaskStop | 反复执行 `true`，说“等待通知” | 模型已称 verifier reward 1.0，但在收尾/等待里空转 |
| linux-049 | 258 Bash | `until docker exec ... grep PIPELINE_DONE; sleep 300` | 构建实际失败：`/opt/osquery/build/ccache: not found`，`make Error 127`；模型却一直等 `PIPELINE_DONE`，没有处理失败 |

证据：

```text
<task>/synthesis/result.json          # status=agent_error, num_turns=301, rc=143
<task>/synthesis/stdout.jsonl         # tool_use 序列
<task>/workspace/.agent-tmp/...       # 026 selfcheck.log, 038 image-build2.log
```

linux-049 的失败是 build 配置（缺 ccache），不是网络；但模型没有在 300 turn 内
识别并修复，属于模型预算/控制循环问题。

### G1-G4 详解与产物链接

#### G1 linux-008：代理凭据写进 main 镜像（复核：成立；ARG 声明正常，传值才是问题）

- 产物：`results/iterate-20261109-05/batch-001/linux-008-osv-2022-110-facebook-zstd/workspace/delivery/project/Dockerfile.main`
  第 7–12 行声明 `ARG HTTP_PROXY/HTTPS_PROXY/...`。**声明 ARG 本身是正常写法，
  不是问题**；
- 引用：`.../delivery/environment/docker-compose.yaml:3` 使用
  `zstd-osv2022-110-main:i05`；
- 真正的问题：构建 main 镜像时把这些 ARG **赋成了带凭据的代理 URL**。Docker
  会把 build-arg 的**值**写进镜像 history/config；Review 用
  `docker history --no-trunc zstd-osv2022-110-main:i05` 看到了完整的
  `HTTP_PROXY=http://<user>:<password>@proxy...`（用户名/密码已脱敏）。

我本地复核过：`docker history --no-trunc` 的 RUN/ARG 行确实包含
`proxy.pjlab.org.cn:23128` 的认证 URL；`docker image inspect` 的 JSON 里没有，
因为它在 history 里，不在顶层 config 字段。所以这不是误判。

含义：谁拿到 main 镜像，谁就能读出代理账号密码；这违反“凭据不进镜像/日志/文件”。
修复：构建 main 时不要传带凭据的 build-arg；用 kkRepo mirror 或 BuildKit
secret，不要用 `ARG HTTP_PROXY` 传真实 URL。client 镜像已经用空 proxy
build-args 构建，是干净的。

自己验证：

```bash
docker history --no-trunc zstd-osv2022-110-main:i05
# 或
docker save zstd-osv2022-110-main:i05 | tar -xO --wildcards '*/config.json' | grep -i proxy
```

#### G2 linux-010：rebuild.sh 的重试循环是死代码（复核：成立）

- 产物：`results/iterate-20261109-05/batch-001/linux-010-osv-2026-713-aous72-openjph/workspace/delivery/private/rebuild.sh`
- 第 8 行：`set -euo pipefail`
- 第 34–43 行：`for attempt in 1..5`，第 38 行执行 MSan decode，第 39 行才 `rc=$?`
- 但 `set -e` 下，第 38 行返回 139 时 shell 立即退出，根本到不了第 39 行，循环失效。

Review 实测：MSan 启动时约 19% 概率 SIGSEGV（139）；`solution.sh` 一次失败，
verifier 就记 `patch_failed`，正确题也会被误判。修复：`... timeout ... || rc=$?`
或循环期间 `set +e`。

#### G3 linux-043：oracle 读错 job 目录（复核：成立，属于竞态）

- 产物：`results/iterate-20261109-05/batch-001/linux-043-cve-2022-0272-detekt/workspace/delivery/private/oracle.sh:27`
- 代码：`latest=$(ls -1 "$JOBS" | sort | tail -n 1)`
- 但公开 Compose 的 client healthcheck 每 30 秒创建一次 benign job；
  `pipeline/harbor.py:target_contract()` 保留了 client 的 healthcheck，
  `pass2fail_verifier._write_compose()` 也没有删除它。
- 结果：oracle 可能读 healthcheck 刚创建的 job，而不是选手提交产生的 job；
  即使选手没触发漏洞，也可能误判，或反之漏判。

修复：每次 submission 生成唯一 run id，healthcheck 用独立目录，oracle 只读该
run id 的 baseline.xml。

#### G4 linux-048：source-recovery 的 sha256 是编造的（复核：成立，哈希不一致是硬证据）

- 产物：`results/iterate-20261109-05/batch-001/linux-048-cve-2016-5844-libarchive/workspace/delivery/project/source-recovery.json`
- 它记录的 vulnerable archive sha256：

```text
27275748c820626b86d43cbe611987ac7f8d2e6aa45d530c9314d29369b33151
```

- 实际 tarball：

```text
results/iterate-20261109-05/batch-001/linux-048-cve-2016-5844-libarchive/
  workspace/delivery/project/src/libarchive-05caadc7....tar.gz
```

实际 sha256：

```text
27275748c820626be748559fc73252a1ea80a31ff3a3823009418d535c310fec
```

前 16 个 hex 相同，后 48 个是编造的；fixed 的哈希也一样。Review 还在
`review-input/trajectory.jsonl` 约 17238 行指出，轨迹里唯一做过的哈希计算是
`sha256sum libarchive-$...`，并没有真正计算完整值。

修复：不允许“凭记忆补全哈希”；source-recovery 必须由实际 `sha256sum` 输出生成，
controller 应重新计算并比对。

### 日志格式（已按 exploit 的习惯调整）

每个 `synthesis/` 现在会保留：

| 文件 | 内容 |
| --- | --- |
| `stdout.jsonl` | Claude Code 的完整原始 stream，包含所有事件；排查底层问题看它 |
| `trajectory.jsonl` | 新 run 的紧凑轨迹：每个 assistant turn、tool_use、tool_result、最终 result，不再包含 `thinking_tokens` 心跳和 thinking 块 |
| `tool-calls.jsonl` | 一行一个工具调用：`turn`、`tool`、`input` |
| `conversation.md` | 人类可读对话：assistant 文本、工具命令、工具结果、最终结果 |
| `result.json` / `stderr.txt` | 进程结果与 stderr |

旧 run 05 的 `trajectory.jsonl` 是 `stdout.jsonl` 的原样拷贝，所以还是 15MB、
含 6.8 万条 thinking 心跳。已经用转换器为 4 道 300-turn 题生成了紧凑版：

```text
<synthesis>/trajectory.compact.jsonl   # 约 0.5MB，带 turn 编号
<synthesis>/tool-calls.jsonl           # 约 230KB
<synthesis>/conversation.md            # 约 460KB
```

对任意旧目录可重新生成：

```bash
python3 -m pipeline.compact_logs   results/iterate-20261109-05/batch-001/<task>/synthesis
```

新启动的 run 会自动写紧凑 `trajectory.jsonl`，`stdout.jsonl` 仍保留全量原始日志。
## 3. 结论与下一步

### 已确认的管线修复

| 问题 | 文件 | 状态 |
| --- | --- | --- |
| FILE-POV private tar 用 PAX，被 BusyBox tar 拒绝 | `pipeline/pass2fail_verifier.py` | 已改为 GNU_FORMAT |
| Harbor 替换 main 镜像后 main healthcheck 失效 | `pipeline/harbor.py` | 已改为 `kill -0 1` |
| FILE 题残留 SVC host_type | `pipeline/run.py` | 已按 route 规范化为 null |
| 缺失 `health_timeout_sec` / `restart_command: null` | `pipeline/task_contract.py` | 已有默认值 |

这些修复不会改变已经启动的 run 05 worker（它们加载的是旧代码）；对下一批/下一个 run 生效。

### 仍需处理

1. **等 10 个 Harbor 题结束**：它们可能改变通过率；不要现在把 run 05 当成最终结果。
2. **review.json 漏 `execution_checked`**：在 REVIEW Prompt 增加完整 one-shot 对象；合同仍保持严格。
3. **300 turn 上限**：4 题都撞上限，评估是否提高 `--max-turns` 或要求 Agent 更早收敛。
4. **review_rejected 的 4 题**：都是交付缺陷（凭据、rebuild 重试、oracle 选错 job、伪哈希），不是基础设施；不应携带，需按 findings 修复后重新审查。
5. **下一批**：优先携带 A/B/C/E 类管线失败题（约 4+2+3+1=10 题），加新题组成 30；模型预算/review 质量题不自动携带。

## 4. 复现证据命令

```bash
cd /nvme/wuyida/新管线开发
python3 .cursor/skills/pipeline-iterate/scripts/iterate.py status \
  --results results/iterate-20261109-05

# 单题证据
T=results/iterate-20261109-05/batch-001/<task>
cat "$T/result.json"
cat "$T/synthesis/result.json"
cat "$T/workspace/review.json"
find "$T/harbor" -name evidence.json -o -name job.log
```

报告中的路径都是当前工作区的绝对/相对可追溯路径；`<task>` 替换为上表任务名即可。