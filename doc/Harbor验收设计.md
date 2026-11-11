# Harbor 验收设计（两次 Agent 跑题 + Pass2Fail）

> 版本：2026-11-10。本文是当前验收逻辑的权威说明，取代此前
> “Harbor gold + null + 工厂差分”的三段式设计。
> 代码入口：`pipeline/harbor.py::accept()`、`pipeline/run.py`、
> `pipeline/supervise.py::strictly_accepted()`。

---

## 1. 一句话

**同一份导出的题包，用 Harbor 跑两次“几乎等于真实做题”的验收：**

- 两次都使用 `--agent claude-code`，不是在 Harbor 里用 oracle 模式；
- 每次让 Agent 工作有限轮数（`--accept-turns`，默认 3）；
- 合成阶段产出的 `ref_poc` 预先挂到 `/workspace/<submission>`，当作 Agent 已经写好的提交；
- 每次 Harbor 收集 artifact、销毁选手环境，再调用同一个 `Pass2FailVerifier`，
  在干净的 vulnerable/patched 两个阶段里判定 Pass2Fail；
- **两次 reward 都是 1.0 才算通过。**

不再跑 Harbor null，也不再跑工厂内 `execute_verify` 差分。

---

## 2. 为什么这样设计

### 2.1 为什么要“两次”

Agent 在做题时会写文件：`/workspace`、可写 bind、目标侧的临时目录等。
如果打包/解包逻辑没有正确保存和恢复可写文件，第一次 Agent 跑完后，
第二次做题时题包可能已经被上一次写脏，导致：

- 原本 vulnerable 的环境被污染；
- patched 阶段看到的不是干净状态；
- 选手/Agent 的提交路径被旧文件影响。

**只跑一次 Harbor 发现不了“恢复逻辑是否真的把题包还原干净”的问题。**
第一次 Agent 跑完后，`accept()` 先恢复 `pristine-binds.tar`，再跑第二次；
第二次必须看到恢复后的干净题包，仍然 Pass2Fail。这样测的是**恢复能力**，
不是“把脏字节继承下去”。

> 注意：每轮 verifier 内部也会在 vulnerable/fixed 两个 phase 前后恢复
> `pristine-binds.tar`；两次 Harbor 验收测的是**跨 Harbor 运行**的恢复，
> 不是 verifier 内部两个 phase。

### 2.2 为什么用 Agent 模式，不用 Harbor oracle 模式

`--agent oracle` 只会执行 profile 里的 `solution/solve.sh`，把参考解复制到
`/workspace`，不模拟真实做题过程。它测不到：

- Agent 在 main 中启动、交互、写文件；
- Harbor 的 artifact 收集路径；
- Agent 可能触碰的可写 bind。

新设计用 `--agent claude-code`：

- 真正启动 Harbor 的 Claude Code agent；
- `--ak max_turns=N` 限制它只工作几轮，避免成本和超时；
- 参考 PoC 通过只读 bind 预置在 `/workspace/<submission>`，
  所以 Agent 不需要自己解题，但会经历真实的启动/交互/收集路径。

### 2.3 为什么删除 null

旧设计的 null 用来证明“空提交得 0”。现在暂时删除，原因：

- 空提交的防护主要由独立 review 检查（oracle 不能信任 stdout、不能只看
  端口/200、不能硬编码 gold、必须有目标侧效果）；
- 两次 Agent 验收都带真实 reference submission，null 不再是主验收路径；
- 如果以后要恢复“空提交不得分”的自动检查，可以再加一次无 mount 的
  Harbor agent run，不需要改 verifier。

**风险**：没有 null 后，如果 verifier 出现“缺提交也返回 1”的 bug，自动验收
发现不了。当前依赖 review 和 verifier 的 `collected_submission()` 逻辑；
这是明确的已知缺口，不是“已经解决”。

### 2.4 为什么删除工厂差分

旧工厂差分直接用 `execute_verify()` 跑最终 profile，不经过 Harbor。它能验证
verifier 逻辑，但不能验证“真实做题路径 + artifact 收集 + 可写文件污染”。
现在两次 Harbor Agent 验收都走真实路径，覆盖更强，所以不再需要工厂差分。

如果两次 Harbor 都通过，说明：

1. 题包能在 Harbor 中启动 main/client；
2. Agent 能在 main 中工作并产出 artifact；
3. Harbor 能收集 `/workspace/<submission>`；
4. verifier 能在销毁选手环境后重建 client+runner；
5. vulnerable 命中、patched 不命中、patched 健康；
6. 第二次运行没有被第一次的可写文件污染。

---

## 3. 两次验收的完整流程

```text
accept()
├─ export()                     # 生成 bundle / harbor-runtime-profile / docker save
├─ load_archives()              # 重新 load 镜像并核对 image ID
├─ extract_pristine_binds()     # 第一次运行前恢复可写 bind
├─ 第 1 次 Harbor agent run
│   ├─ Harbor 启动 main + client
│   ├─ main 挂载：/usr/local/bin/claude（本地可执行文件）
│   │            /workspace/<submission>（reference PoC，只读）
│   ├─ claude-code agent 最多 --accept-turns 轮
│   ├─ Harbor 收集 /workspace/<submission>
│   ├─ 销毁选手环境
│   └─ Pass2FailVerifier 启动私有 client+runner
│       ├─ vulnerable phase：health → submission → oracle
│       └─ fixed phase：solution（patch/build/replace/restart）→ patched_health →
│                        同一 submission → oracle 必须 exit 1
│   → reward 必须 1.0
├─ extract_pristine_binds()     # 第二次运行前恢复可写 bind
├─ 第 2 次 Harbor agent run（同一 profile，恢复后的题包）
│   → reward 必须 1.0
└─ status = passed iff 两次 reward 都是 1.0
```

每次 `harbor run` 的 subprocess 前后，`_harbor_run_fresh()` 都会恢复可写 bind；
因此循环结束后不需要再额外恢复一次。

### 3.1 参考 PoC 怎么“当作 Agent 写的”

`accept()` 在 profile 的 `tests/private/` 里找：

```text
reference_<submission_mode>
```

例如 SVC / FILE-EXPLOIT 是 `reference_exploit.py`，FILE-POV 是
`reference_input.bin`。然后用 Harbor 的 `--mounts` 只读挂到：

```text
/workspace/exploit.py      # SVC / FILE-EXPLOIT
/workspace/input.bin       # FILE-POV
```

Agent 启动后看到文件已经在 `/workspace` 里，可以读、可以继续工作；
Harbor 最终收集的也是这个路径。

### 3.2 Agent 轮数

`pipeline/run.py --accept-turns` 默认 **3**：

```bash
.venv/bin/python -m pipeline.run \
  --sample ... --results ... \
  --only <task> --resume \
  --accept-turns 3
```

传给 Harbor：

```text
--agent claude-code
--ak max_turns=3
--ak version=<本机 claude --version>
--ak disallowed_tools=WebSearch,WebFetch
--model <pipeline --model>
```

`max_turns` 只是防止 Agent 长时间工作；参考 PoC 已经预置，不需要它真的解题。

### 3.3 两次之间恢复可写 bind

第一次运行后，`accept()` 调用：

```python
extract_pristine_binds(profile, profile / "environment")
```

把 profile 的可写 bind 恢复成 `pristine-binds.tar` 封存的状态，再跑第二次。
第二次必须在这个恢复后的题包上仍然 Pass2Fail；如果恢复逻辑坏了，第二次会
看到第一次的脏字节并失败。

循环结束后**不再**额外调用 `extract_pristine_binds()`。`_harbor_run_fresh()`
在每次 `harbor run` 的 `finally` 里已经恢复；正常返回和异常退出都会走到那里。

`accept()` 里第一次和第二次运行前的显式恢复仍然保留：它们让验收序列本身
可读，也防御 `harbor_run()` 内部实现变化；但真正保证 player 启动前干净的是
`_harbor_run_fresh()` 的跑前恢复。

`load_image.py --task` 的预跑恢复调用的也是同一个
`pristine_binds.extract_pristine_binds()`，区别只是调用者：一个在交付包外部
加载镜像后执行，一个在 `accept()` 的验收序列里执行。

`Pass2FailVerifier` 自身在 `verify()` 入口/退出和 `fresh_verify()` 的
`finally` 里也会恢复 public `task_dir/environment`；所以 verifier 异常退出时，
题包同样会被还原。

注意恢复不只发生在两次 Harbor run 之间：`_harbor_run_fresh()` 在真正执行
`harbor run` 的 subprocess **之前**和 `finally` 里也各恢复一次。因为 player
先于 verifier 启动，只在 verifier 入口恢复对当前 player 已经太晚。完整机制
和外部跑题注意事项见 [可写 Bind 恢复说明](可写Bind恢复说明.md)。

如果第一次失败，`accept()` 立即停止，不再跑第二次；结果是 failed。
如果第二次失败，保留两次的 `jobs/*/result.json` 和 verifier evidence 供排错。

---

## 4. 结果 JSON

`results/<run>/<task>/harbor/result.json` 新形状：

```json
{
  "schema_version": 3,
  "stage": "harbor",
  "status": "passed",
  "task_id": "...",
  "export_task_id": "...",
  "manifest": {...},
  "acceptance_runs": [
    {"attempt": 1, "status": "passed", "reward": 1.0, "agent": "claude-code", "result": ".../jobs/...-accept-1/result.json"},
    {"attempt": 2, "status": "passed", "reward": 1.0, "agent": "claude-code", "result": ".../jobs/...-accept-2/result.json"}
  ],
  "acceptance_rewards": [1.0, 1.0]
}
```

`pipeline/supervise.py::strictly_accepted()` 的新口径：

```python
status == "passed"
and review.passed is True
and len(acceptance_runs) == 2
and all(run.reward == 1.0 for run in acceptance_runs)
```

旧的 `gold` / `null` / `differential_from_final_bundle` 字段只在读取历史
results 时兼容，不再写入新结果。

`publish_bundle()` 的 manifest 记录：

```json
{"status": "accepted", "acceptance_runs": 2, "acceptance_rewards": [1.0, 1.0]}
```

---

## 5. 每次 verifier 内部仍然做什么

两次 Harbor 验收共用同一个 `pipeline/pass2fail_verifier.py`：

### vulnerable phase

```text
up client+runner
upload_private -> client:/private
health          -> runner 发正常协议请求
submission      -> runner 以 uid 65534 跑 exploit.py
oracle          -> client 内检查目标侧效果，exit 0
```

### fixed phase

```text
新建全新 Compose project
up
upload_private
health
solution        -> client 内应用官方 patch + 离线 build/replace + restart
patched_health  -> 正常协议请求仍然成功
同一份 submission
oracle          -> 必须 exit 1
```

只有 vulnerable oracle=0 且 fixed oracle=1 且 patched_health=0 才
`status=this_bug`、reward=1.0。这就是每次 Harbor run 里的 Pass2Fail。

---

## 6. 分支差异

| 分支 | reference 挂载 | 提交路径 | 执行位置 |
|---|---|---|---|
| SVC-EXPLOIT | `reference_exploit.py` | `/workspace/exploit.py` | runner（uid 65534） |
| FILE-EXPLOIT | `reference_exploit.py` | `/workspace/exploit.py` | runner（uid 65534） |
| FILE-POV | `reference_input.bin` | `/workspace/input.bin` | client 上的 `public_runner` |

Agent 模式对三个分支相同；区别只在 Harbor 收集的文件名和 verifier 执行提交的位置。

---

## 7. 失败与恢复

| 现象 | 处理 |
|---|---|
| 第 1 次 reward != 1.0 | 停止，不再跑第 2 次；`status=failed` |
| 第 2 次 reward != 1.0 | `status=failed`，保留两次 jobs/evidence |
| Harbor 启动/收集失败 | `status=error`，保留 `jobs/<name>.log` |
| verifier `infra_error` | 看 `jobs/*/accept-*/<trial>/verifier/evidence.json` 的 `error_stage` |
| 可写 bind 污染 | 对比两次 evidence 和 `pristine-binds.tar`；第二次失败优先怀疑打包/恢复 |
| 需要重跑验收 | `pipeline.run --resume` 或 `--review-delivery`，不重跑合成 |

---

## 8. 与旧设计的对比

| | 旧设计 | 新设计 |
|---|---|---|
| Harbor gold | `--agent oracle`，参考解放进 `/solution` | `--agent claude-code`，reference 预挂 `/workspace` |
| Harbor null | 有 | **删除** |
| 工厂差分 | `execute_verify` 直接跑 profile | **删除** |
| 验收次数 | gold + null + 工厂差分 | 两次完整 Harbor agent run |
| 检测可写文件恢复 | 没有专门覆盖 | 第一次后恢复 bind，第二次在恢复后的题包上再跑 |
| 参考解是否真的经历 Agent 路径 | 否，oracle 只复制文件 | 是，Agent 启动/交互/被收集 |
| 结果字段 | `gold` / `null` / `differential_from_final_bundle` | `acceptance_runs` / `acceptance_rewards` |

---

## 9. 已知限制

1. **没有 null**：空提交自动防护缺失，依赖 review 和 verifier 的
   `collected_submission()`。这是暂时接受的缺口。
2. **Agent 可能不真的“工作”**：reference 已预置，`max_turns` 只是上限；
   如果 Agent 直接退出，仍然会走 artifact 收集，但不会模拟完整解题。
   这是“跑题路径 + 污染检测”的折中，不是模型能力评测。
3. **凭据传递**：Agent 需要 `ANTHROPIC_API_KEY` / `ANTHROPIC_BASE_URL`，
   当前通过 Harbor `--ae` 传给 agent；`jobs/` 目录应按敏感材料管理。
4. **两次运行成本**：每个通过题多一次完整 Harbor + verifier 运行；这是
   为检测可写 bind 恢复能力付出的成本。
5. **没有 verification.json**：合成 Agent 不再写自检报告，审查只读
   `delivery/`、`live.chat.md` 和 `tool-calls.jsonl`；没有
   `review-input/self-check.json`。
6. **旧结果兼容**：`strictly_accepted()` 仍读旧 `gold/null/differential` 字段，
   仅用于历史 results；新结果不会写这些字段。

---

## 10. 代码位置

| 文件 | 作用 |
|---|---|
| `pipeline/harbor.py::accept` | 导出、两次 Harbor agent run、恢复 bind、状态 |
| `pipeline/harbor.py::_harbor_run_fresh` | `--agent claude-code`、mounts、max_turns、env |
| `pipeline/run.py --accept-turns` | 验收 Agent 轮数，默认 3 |
| `pipeline/pass2fail_verifier.py` | 每次 Harbor run 内部的 vulnerable/fixed Pass2Fail；文件内定义通用 `Pass2FailVerifier` 类 |
| `pipeline/pristine_binds.py` | 可写 `./` bind 封存/恢复；`python3 bin/pristine_binds.py <profile>` 可手工恢复 |
| `pipeline/supervise.py::strictly_accepted` | 两次 `acceptance_runs` 都 1.0 才算严格通过 |
| `doc/可写Bind恢复说明.md` | 为什么恢复、wrapper 是什么、三层恢复点和边界 |

---

## 11. 交付给外部使用

### 11.1 题目形态

每个题目目录是一个自包含的 Harbor task：

```text
<bundle>/
├── task_id_all.jsonl          # 每行 {"task_id": "..."}
├── bin/load_image.py          # 加载指定任务/全部镜像并恢复可写 bind
├── shared-images/             # 多题共享的 agent/verifier 镜像
└── <task-id>/
    ├── image-lock.json        # role/ref/archive 镜像索引
    ├── images/                # target / sidecar / 专用 agent 镜像
    ├── harbor-runtime-profile/    # Harbor --path 指向这里
    │   ├── task.toml              # environment_mode=separate；不写 import_path；不写超时
    │   ├── environment/           # 公开 main + client
    │   ├── pristine-binds.tar     # 可写 ./ bind 的 sealed 快照
    │   └── bin/
    │       ├── pass2fail_verifier.py   # 通用 verifier 类（所有题同一份）
    │       ├── pristine_binds.py
    │       ├── docker_ipam.py
    │       └── task_contract.py
    └── acceptance.json            # 只读验收证据
```

### 11.2 跑题/评测

使用 Harbor 0.22.0。加载单题镜像，并在返回前恢复该题可写 bind：

```bash
python3 <bundle>/bin/load_image.py --task <task-id>
```

`load_image.py --task` 只加载本题 `images/` 里的镜像；`shared-images/` 由 host
一次性 `--shared-only` 预加载，不随每题重复加载。不带 `--task` 会先加载 shared，
再加载全部任务；`--no-restore` 可关闭自动恢复。
它还可以用 `--run` 包住一次 `harbor run`，在命令前后各恢复一次：

```bash
PYTHONPATH="$PWD" python3 <bundle>/bin/load_image.py --task <task-id> \
  --run harbor run --path "$PWD" ... --verifier bin.pass2fail_verifier:Pass2FailVerifier
```

然后每道题单独跑一个 trial：

```bash
cd <bundle>/<task-id>/harbor-runtime-profile
PYTHONPATH="$PWD" harbor run \
  --path "$PWD" \
  --agent <你的-agent> \
  --n-attempts 1 --n-concurrent 1 \
  --jobs-dir <jobs> --job-name <unique-name> --yes \
  --verifier bin.pass2fail_verifier:Pass2FailVerifier
```

- `task.toml` 只写 `environment_mode="separate"`，**不写 verifier 的
  `import_path`**；和 `exploit` 一样，用 `--verifier` 指定类、用
  `PYTHONPATH` 让宿主 Python 找到它；
- `bin/pass2fail_verifier.py` 是**通用 verifier 类**，所有题目共用同一份；
  题目差异全部从 `task_dir/tests/private/task.json` 和私有目录读取；
- 不需要往 main 或 verifier 容器里“挂一个类”；类在 Harbor 宿主进程里运行；
- 同一宿主进程判多道题时，类只 import 一次；因为代码相同，不存在“串题”
  问题。不要为单题修改 verifier 代码。

判分与预算约定：

- `task.toml` 不写 `[agent] timeout_sec`、`[verifier] timeout_sec`、
  `build_timeout_sec`；超时由外部 Harbor 配置控制。
- agent 没提交/没打中 → reward 0（判分完成）。
- target 起不来、oracle 异常、patch 无法应用等判分失败 → `VerifierInfraError`
  抛出，不写 reward，Harbor 记 failed；`tests/test.sh` 不再写占位 0。
- verifier 退出时会恢复 public `environment` 的可写 bind（`fresh_verify` 的
  `finally` + `Pass2FailVerifier.verify`），跑完不会污染题包。

### 11.3 并发与可写 bind

- **不同题目**可以并发：每题有独立 `task_dir`、独立镜像 tag、独立 Compose
  project 和 IPAM /24；前提是镜像 tag 全局唯一（导出合同已要求）。
- **同一题目目录**不要并发跑多个 trial：公开环境的可写 `./` bind 是同一个
  目录，两个 player 会互相踩。需要并发同一题时，每个 trial 复制一份
  `harbor-runtime-profile`。
- 每次做题前，`load_image.py --task <task-id>` 会加载镜像并恢复可写 bind；
  这就是预跑 wrapper 的外部入口。也可以手动执行：

```bash
PYTHONPATH="$PWD" python3 bin/pristine_binds.py "$PWD"
```

  本管线自己的 `accept()` 在第一次、第二次运行前显式恢复；真正保证
  **player 启动前**干净的是 `harbor.py::_harbor_run_fresh`，它在执行
  `harbor run` 的 subprocess 前后各恢复一次。循环结束后不再单独恢复，因为
  wrapper 的 `finally` 已经完成。

  `Pass2FailVerifier.verify()` 另外在入口和退出时恢复 public
  `task_dir/environment`，用于外部直接调用 Harbor 的场景兜底；但外部
  player 仍然先于 verifier 启动，因此最稳的做法是每个 trial 用独立
  profile 副本，或在 `harbor run` 外面套一层“恢复 → 运行 → 恢复”，
  和 `exploit` 的 `harbor_package_binds` 做法一致。

### 11.4 和 `exploit` 的 verifier 区别

两边现在是**同一种形式**：

- 都用 `environment_mode="separate"`；
- `task.toml` 都不写 verifier 的 `import_path`；
- 都用 `--verifier <module>:Pass2FailVerifier` + `PYTHONPATH` 从宿主加载
  一个通用 `BaseVerifier` 类；
- 都是“选手环境销毁后，在宿主重新起 client+runner，做 vulnerable/fixed
  Pass2Fail”。

区别只在类的交付位置：

| | 新管线（统一后） | exploit |
|---|---|---|
| 类位置 | `harbor-runtime-profile/bin/pass2fail_verifier.py` + 同目录 `legacy_pass2fail_verifier.py` | 仓库级 `orchestrator/export/separate/pass2fail_verifier.py` |
| `PYTHONPATH` | 指向 `<task>/harbor-runtime-profile` | 指向 exploit 仓库 |
| `--verifier` | `bin.pass2fail_verifier:Pass2FailVerifier` | `orchestrator.export.separate.pass2fail_verifier:Pass2FailVerifier` |
| 题目差异来源 | `task_dir/tests/private/task.json` + 私有文件 | 同一份 runtime 包 + private 文件 |

新管线现在把老 exploit 的 `test.sh` 判分也收进了同一个 `Pass2FailVerifier`：
profile 里有 `tests/private/task.json` 时走 host-oracle；没有 `task.json`、
但有 `tests/test.sh` 时走 `legacy_pass2fail_verifier.py` 的 judge-container
策略。类文件和 legacy 策略都复制进 `harbor-runtime-profile/bin/`，评测机不需要
本仓库，适合分布式沙箱。

也就是说，两条管线的跑题命令形状完全一样，只是模块名和 `PYTHONPATH`
指向不同；新管线内部已经是一套类，老 exploit 题可以直接使用同一套策略。