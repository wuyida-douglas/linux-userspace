# 2026-11-10 合成题审计 — 需要改管线的项（按反馈修订）

> 范围：`results/iterate-20261109-08/batch-001`、`results/iterate-20261110-01/batch-001`、
> `results/iterate-20261110-01/batch-002` 中全部 `status=passed` 的交付，共 75 条 / 72 个唯一 CVE。
>
> 本文件只保留**根因在管线 / prompt / verifier / export，且需要改代码或流程**的项。
> 不再分等级；不记录已复核为低概率的风险；不记录题面难度设置（0day/1day/nday）；
> acceptance null/negative 暂不列入（当前先按你的决定保留两次 gold）。

## 0. 原则

1. **CVE meta 可能是错的。** route 阶段不因为 meta 不一致丢候选；要求的是题目**自洽**：
   instruction/题目演示漏洞 A → oracle 必须验证 A → fixed 必须真的修 A。
2. **pass2fail 是主判据。** 非 CVE 效果如果在 fixed 上也触发，会被 fixed phase 拒绝；
   只有三类例外需要管线额外处理（§2）。
3. 不记录单题包装问题；只保留会影响**一批题**或**管线正确性**的改动。
4. **Review 必须检查可解性。** verifier 好不代表题可做；agent 只有 `main` + `instruction.md`。
   `main` 必须有 instruction 声称的源码/工具；SVC 必须能从 main 访问 `client:PORT`。
   否则 review 拒绝。能在 review 检查的，不写代码；能改 prompt 的，不改代码。

**修复位置**

| 项 | 位置 |
|---|---|
| §1 自洽 | SYNTHESIZE + REVIEW prompt |
| §2 oracle 因果性 | SYNTHESIZE + REVIEW prompt |
| §3 导出 | 代码（`harbor.py` publish/export） |
| §4 rename 路径 | 代码（`rename_results.py`） |
| §5 可解性 | REVIEW prompt（不用 acceptance 脚本） |
| §6 小项 | contract/review prompt |

---

## 1. 题目自洽：instruction 的 A == oracle 的 A == patch 修的 A

**现象**

- `cve-2018-20552`：instruction 演示 `packet2tree` L4 over-read（A）；supplied patch
  2595c903（4.3.1）只改 `src/common/utils.c` 的零长度守卫（B），`src/tree.c` 没动。
  agent 按 A 构造输入，在 vulnerable 上崩、在 fixed 上也崩（因为 fixed 没修 A），
  反而被判 `other_bug`；只有加一条零长度 record 让 fixed 提前退出才能过。
- `osv-2021-453`：`private/patch.diff` 只注释掉 `fuzzing/Http.cpp` 的 harness 调用，
  parser 未改；如果题目标成 OSV-2021-453 的 parser WRITE，instruction/oracle/patch 不自洽。

**这不是 route/meta 问题**

- CVE/OSV 的 fixed 字段确实可能是错的（4.3.1 的 release note 声称修 #530，但上游
  v4.3.3 的 CHANGELOG 才把 #530 移过去；真正改 `tree.c` 的是 `53919090`）。
- 所以不要 route 阶段拒掉候选；要在 **synthesis/review** 保证自洽。

**管线改动（SYNTHESIZE + REVIEW prompt，不改代码）**

- synthesis：
  - 如果 supplied `fix.diff` 没有触达被演示的文件/函数，去 upstream history 恢复真正
    修 A 的 commit（`git log -S "<vulnerable line>"`、advisory commit、tag 对比）。
  - 或者把演示的 A 改成 fix 真正修的 B；不要构造“selector 差分”（用另一条记录让
    fixed 提前退出）。
- review：检查三条一致，不一致直接拒：
  1. `instruction.md` 描述的漏洞 A；
  2. `oracle.sh` 判定的漏洞 A；
  3. `patch.diff` 实际修的漏洞 A。
- 具体负例：`cve-2018-20552` 的 instruction 说 `packet2tree`，patch 不碰 `tree.c`，
  应判不一致；`osv-2021-453` 的 patch 只改 harness，若题目标是 parser，应判不一致。

**验收**

构造一个“instruction 的 A != patch 的 A”的负例，review 必须拒绝；
构造一个“fix 不触达 A”的正例，synthesis 必须触发 recovery。

---

## 2. 差分之外的 oracle 漏洞（pass2fail 已覆盖大部分）

**先确认你的理解**

如果 oracle 接受一个非 CVE 效果，而 patch 没修它，那么 fixed phase 也会触发，
`fixed.triggered=true`，reward 0。**所以 pass2fail 本身挡住了大多数“任意 crash/500”。**
只有下面三类例外需要管线额外处理。

**修复位置：SYNTHESIZE + REVIEW prompt，不改代码。**

### 2.1 oracle 自证（vulnerable 侧信号不是提交物造成的）

- `cve-2024-52549`：oracle 的 condition 1 是自己对 vulnerable target 的探测
  （`oracle.sh:35-44`）；condition 2 只要求 journal 里有一个带全部 48 个 slot 值的
  POST + 8 个任意 GET。agent 的提交物可以是 no-op；fixed 失败是因为 oracle 自己的
  probe 失败，不是提交物真的泄露。
- 管线改动：vulnerable 侧信号必须来自**提交物的效果**，不能来自 oracle 自己的 probe；
  probe 只能作为 benign/负控，不能作为“vulnerable 存在”的证据。

### 2.2 提交物可写/可伪造证据

- `cve-2020-15358`：oracle 读 `/tmp/pov/last-run.log`，该文件由同 uid（65534）runner
  创建；提交的 SQL 可用 `writefile()` 覆写日志、`.shell kill -ABRT` 造出 `runner_exit=134`。
- `cve-2026-3285`：`/var/pov` 是 733，Berry 提交物可用 `os.system` 写 `run.log` + status。
- 这类提交物可以只在 vulnerable 上伪造、fixed 上不伪造，pass2fail 抓不到。
- 管线改动：证据文件 root-owned、提交 uid 不可写；oracle 重跑提交物时降权到 65534；
  不读 runner/target 可写日志。

### 2.3 phase-aware 提交物 + 宽 oracle

- crash-only SVC：`cve-2022-24834`（任意 ASan heap-buffer-overflow）、
  `cve-2026-9698`（任意 rc>=128）、`cve-2021-45773`（任意非零 EXIT）、
  `cve-2017-10671`（只 grep ASan）、`cve-2024-1765`（任意 134/137）。
- any-file：`cve-2026-25635`（`/tmp/pwn` 任意非空文件）。
- 如果提交物先探测版本/行为，只在 vulnerable 上触发一个非 CVE crash，fixed 不触发，
  pass2fail 会通过。
- 管线改动：oracle 必须归因到 CVE 的函数/帧/效果；增加负控（另一种 crash、伪造日志、
  全值 POST、benign 输入）必须判 absent。

**验收**

每个 oracle 带一个“弱 oracle 会过、正确 oracle 不会过”的负控；在 CI 里跑。

---

## 3. 导出：对齐飞书《CVE靶场交付格式-第二版》

文档：<https://aicarrier.feishu.cn/wiki/ENbHwnS0ciy2CgkojPzc0ZPinkf>
（标题：CVE靶场交付格式-第二版；docx token `G6lDd5QOzoe3btxECb3crTRunoh`）

### 3.1 飞书要求的布局

单任务：

```text
<CVE-ID>/
├── image-lock.json
├── images/*.tar.gz
└── harbor-runtime-profile/
    ├── task.toml
    ├── instruction.md
    ├── environment/
    │   ├── docker-compose.yaml
    │   └── assets/
    └── tests/test.sh
```

批量：

```text
<bundle>/
├── task_id_all.jsonl
├── bin/load_image.py
├── shared-images/          # 共享 agent 镜像
├── <task-id-1>/
└── <task-id-2>/
```

关键要求：

- `image-lock.json` 记录每个镜像，共享镜像指向 `../shared-images/...`；
- 所有 compose 引用的镜像都要在 `images/` 或 `shared-images/` 的归档里；
- **不要在线 build**；任务目录/`environment/`/`tests/` 不要留 Dockerfile；
- `task.toml` 不设任何 timeout；不要 `network_mode: none` / `allow_internet: false`；
  用 `public`；
- compose 不要注入代理变量；最终交付镜像不要带代理；
- 共享 agent 镜像放 `shared-images/`，低频镜像放任务 `images/`，不要打成一个巨包。

### 3.2 当前差距（这里需要改代码）

| 差距 | 证据 | 改动 |
|---|---|---|
| 31/75 个导出缺共享 agent 归档 | 现有 root 仍是旧 `_runtime`，只有 `verifier.tar.gz`；`20261109-production` 9、`20261110-production` 4、`20261110-batch-002` 17、`20261110-resume-fixes` 1 | `publish_bundle` 每次合并/校验 `shared-images`；不能“root 没有才搬”（`harbor.py:915-917`） |
| `image-lock.json` 与归档不一致 | 旧导出用 `_runtime`；新代码用 `shared-images` | 导出后跑 `load_image.py --task` 在 fresh host 验证每个 task 的所有镜像可解析 |
| target 镜像含 gold/private/patch | `linux-041` `/opt/private/gold-input.bin`；`linux-039` `/tmp/exploit.car`；`linux-003/059` `/private/*`；`linux-023` patch 中间 layer | 导出前扫 layer/history；命中即拒绝；删掉构建期副本 |
| 代理凭据在镜像里 | 7 题 / 12 镜像的 history/config 有 `http://<user>:<password>@proxy...` | 用 build secret，不用 `ARG/ENV`；轮换凭据；导出前扫描 |
| 重复/陈旧导出 | `harbor-resume-20261109` 16 个与更新 root 重名；`linux-013` 有 `:2`/`:3` 两个 accepted | 每个 task id 只保留一个 accepted；旧版本 quarantine；导出名从 frozen task id 派生 |
| `task.toml`/compose 合同 | 需对齐飞书：无 timeout、无 `network_mode: none`、无代理 env、无 Dockerfile | 导出前契约校验 |

**说明**

- `private/` 随 bundle 交付是正常的；这里说的是 **target 镜像里多出来的 gold/private 副本**
  和 **凭据**，不是“private 不该在产物里”。
- target 镜像不会挂进 agent 的 `main`；所以这不是 agent 做题时的 hack 风险，而是
  **交付产物卫生**（见 §5）。

---

## 4. `rename_results.py`：自动改名后的路径过期

**这里需要改代码。**

**它是什么**

- 不是手工脚本；是 `pipeline/supervise.py:142` 在 batch 结束后自动调用的改名实现。
- 作用：把内部 `linux-027-cve-...` 改成 `cve-2018-20552-file-pov`（`display_task_id`），
  方便导出。

**问题**

- `pipeline/rename_results.py:56-57` 只更新 `result.json.folder_name`，没有重写
  `harbor.gold.result` / `harbor.null.result` / `acceptance.json` 里的绝对路径。
- 75/75 的 gold/null 路径仍指向改名前的目录；job 实际存在，但自动化跟路径会误判 missing。

**管线改动**

- rename 时重写这些路径；或者存相对 job basename，由读取方拼接。
- 验收：rename 后 `test -f "$(jq -r '.harbor.gold.result' result.json)"` 为真。

---

## 5. Review 必须检查可解性（prompt，不是代码）

**原则**

verifier 设计得再好，如果 agent 的 `main` 里没有源码/工具、或者 SVC 的 target
从 main 不可达，题就是不可做的；review 必须 `passed=false`。

**review 怎么查**

- **FILE-POV**：agent 只有 main + instruction；target 是一次性 runner，没有 live shell。
  - `docker run --rm --network none <main> sh -c 'test -d <instruction 声称的源码路径>; command -v <工具>'`
  - 如果 instruction 说“源码在 `/opt/...-src`”，main 里必须真的有；否则 reject。
  - 不要求 target 可交互；要求 main 有构造输入所需的源码/分析工具。
- **SVC**：main 必须能访问 target 的公共协议。
  - 启动 public Compose，从 main 执行 `curl client:PORT/...` 或等价协议探测；
  - instruction 必须写清楚 `client:PORT`；
  - 如果 main 打不到 target，或 instruction 的 endpoint 不对，reject。
- 任何“只能靠 host-only/private/未说明材料才能解”的题，reject。
- review 可以启动 public Compose 做 main→client 探测；不要跑 private differential。

**为什么放在 review**

- 这是“题目是否可解”的判断，不是自动脚本能可靠判断的；
- 不需要改 acceptance 代码；改 REVIEW prompt 即可。

---

## 6. 小项（需要 contract/流程修改）

| 项 | 证据 | 改动 |
|---|---|---|
| `linux-034` public compose `expose: ["8080"]` | `environment/docker-compose.yaml:10` | contract 禁止 `expose`，或明确内部-only 例外 |
| `linux-042` 有 `db` sidecar | compose | 明确 sidecar 白名单/合同 |
| 48/75 review 仍是旧四字段 schema | `workspace/review.json` | 统一到 `{passed, evidence}`；resume 兼容旧格式 |
| `harbor_export/janet/` stray export 无 `acceptance.json` | 目录 | 导出前校验 acceptance；清理 stray |

---

## 7. 建议顺序

1. **题目自洽**（§1）：synthesis 的 fix recovery + review 的 A==A==A。
2. **oracle 因果性**（§2）：去掉 oracle 自证、提交方可写证据、宽 oracle；加负控。
3. **导出对齐飞书**（§3）：`shared-images`、`image-lock`、无 gold/凭据、去重、fresh-host 加载。
4. **路径与合同**（§4/§6）：rename 路径、expose/sidecar/schema、stray export。
5. 每项都加负例测试；新批次必须跑这些测试才能发布。