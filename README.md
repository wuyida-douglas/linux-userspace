# Linux 用户态漏洞题目管线使用说明

把固定漏洞候选池中的 **CVE × 仓库 × 修复候选** 变成可审计的 Harbor 题包。
主流程是：固定抽样（或全量）→ 定点 S3 下载与校验 → 路由 → 分支合成 →
独立审查 → 两次 Harbor Agent 跑题 + Pass2Fail 验收。

本 README 面向后续负责运行和 scaling 的工程同学。**当前是按操作更新的
开发版，不是已完成多租户 scaling 的产品。** 运行前阅读第 2、9 节；输入
预处理的逐字段解释见 **[输入下载与预处理](doc/输入下载与预处理.md)**。

## 1. 和 exploit 管线的区别

exploit 管线按 CVE 下载现成 `{source}_{CVE}/` 目录，并从题单 JSONL 取一行
写成 `meta.exploit.json`，见 `../exploit/README.md` 的“数据准备”。

新管线多了固定样本和证据审计：

1. 校验冻结候选池，再按 seed 固定抽取实例（scale-up 时用 `--all` 准备全池），
   不先挑容易题；
2. 只下载所选 candidate 的 `prefix/` 和 `fix.diff`，不整桶复制；
3. 匹配 candidate/仓库，重建白名单 `meta.json`，验证源码、补丁与缓存；
4. 每位置保留下载失败，不因缺输入而偷换样本；
5. 启动任务时复制只读输入，并生成 `alternate-candidates.json` 备用修复索引。

所有下载、格式检查、摘要与元数据精简都是 **Python 脚本** 完成的，不调用
模型。`complete` 仅表示输入完整且格式合格，不表示补丁一定是该 CVE 的真实
安全修复，更不表示题目通过。

在**交付和跑题形式**上，新管线刻意与 `exploit` 对齐：`task.toml` 不写
verifier 的 `import_path`，统一用 `--verifier <module>:Pass2FailVerifier`
加 `PYTHONPATH` 从宿主加载一个**通用 verifier 类**。每道题的差异来自
`task_dir` 下的 `tests/private/task.json` 和私有文件，不来自 verifier 代码。
两条管线跑题时只是模块名和 `PYTHONPATH` 指向不同，命令形状完全一样。

## 2. 环境与安全边界

### 2.1 前置依赖

- Linux 金属机、足够的本地磁盘、Docker Engine 与 Compose v2；
- Python 3.12（当前验证版本），`rclone`；
- 项目 `.venv`，至少包含 `PyYAML`、`anthropic` 和 Harbor CLI `0.22.0`；
- 模型网关的环境文件；S3 remote 的 rclone 凭据；
- 可访问的官方上游、包镜像和 Docker Hub mirror，见
  [裸金属网络约定](config/bare-metal-network.md)。

当前仓库没有 `requirements.txt`/`pyproject.toml`，新机器需要先固定一份
依赖清单再作为标准镜像交付，不能假设任意 Python 环境都兼容。

在当前开发机可检查：

```bash
cd /nvme/wuyida/新管线开发
.venv/bin/python -c 'import yaml, anthropic; print("Python dependencies OK")'
.venv/bin/harbor --version                 # 0.22.0
rclone version
config/bin/docker version
config/bin/docker compose version
test -r /nvme/wuyida/env                  # 不 cat，不打印密钥
```

不要把模型/S3/代理密钥写进 Git、Prompt、命令参数、题目文件或镜像。

### 2.2 当前运行模型不是最终多租户隔离

合成 Agent 使用宿主 Docker/Compose，不启动 DinD；交付的选手容器不能获得
Docker socket。管线为每题分配 Compose project 和 IPAM，限制公开交付的
权限与挂载，但**共享宿主 Docker 不是恶意任务之间的最终安全边界**。

scaling 前必须由工程负责人明确每 attempt 的隔离方案（例如经过审计的
私有 DinD 或 VM/microVM）、磁盘/内存/并发额度和清理策略。不要仅因为提高
`--concurrency` 就把开发环境称为多租户生产平台。

当前 `pipeline/harbor.py` 使用仓库 `.venv/bin/harbor`，Docker/IPAM 也带有
本机配置。换机器时先确认路径和 wrapper，不要硬编码另一位开发者的 home。

## 3. 数据从哪里来

### 3.1 冻结候选池

默认生产池（经过 S3 可用性过滤）：

```text
data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl
```

原始 LLM 打标输出保留在 `data/frozen-pool-20261109/candidates-kept.jsonl`
（23,873 行），仅用于审计；`scripts/filter_pool_by_s3.py` 从它去掉两类
**确认无法下载**的行：

- S3 上既没有 `osv_<CVE>` / `cvelist_<CVE>`，也没有任何生态别名目录
  （如 `osv_UBUNTU-CVE-...`）；
- 别名目录存在，但没有与该行 candidate 匹配的候选。

过滤结果：**22,138 行**，移除 1,735 行；其中 601 行通过别名恢复，
1,730 行完全无目录，5 行别名目录不含候选。报告见
`data/frozen-pool-20261109/pool-availability-20261109.json`。

`pipeline.prepare` 在 S3 调用之前强制验证：

- 22,138 个唯一 `instance_id`；
- 每行 `metadata_label.label == keep`；
- 文件 SHA-256 为
  `565bdf5914152b3a4f2a00f44c09cc85a38f1b85ae8d42bb833a72c38579e941`。

它是已筛选的候选集合，不是漏洞可交付性的保证。候选池构建脚本位于
`scripts/`，日常固定样本生产**不要重新随机筛选或改写候选池**。

### 3.2 S3 布局和凭据

默认 remote：

```text
p_huawei_hdd1:private-data-3/DataWheel/en-code-osv-nvd/file
```

每题只探测有限的已知对象：

```text
<remote>/osv_<CVE>/meta.json
<remote>/cvelist_<CVE>/meta.json
<remote>/<source>_<CVE>/candidates/<candidate-id>/prefix/
<remote>/<source>_<CVE>/candidates/<candidate-id>/fix.diff
```

rclone 配置必须包含名为 `p_huawei_hdd1` 的 S3 remote。若使用自定义配置
文件，在调用前设置 `RCLONE_CONFIG=/安全路径/rclone.conf`。也可传
`--remote <配置中的remote名>:<bucket>/<前缀>` 切换到其他数据源。

**不要对整个 bucket 做 list/copy。** 脚本先按已知 CVE 和 candidate 定位，
目录下载后逐文件核对字节数；缓存按 SHA-256 复核。不会自动拉 `base/`、
`fix/`、`.git/` 或其他 candidate。

## 4. 从 S3 建立一个新固定样本

以下命令只做数据准备，不调用模型。请替换样本名、数量和 seed；已有目录
代表已有实验，不要换个参数覆盖。

```bash
cd /nvme/wuyida/新管线开发

# 可选：只固定抽样，完全不访问 S3。
.venv/bin/python -m pipeline.prepare \
  --input data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl \
  --output samples/my-fixed100-s20261120 \
  --count 100 --seed 20261120 --sample-only

# 下载并预处理同一固定样本；workers 仅控制下载并发，最大 30。
.venv/bin/python -m pipeline.prepare \
  --input data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl \
  --output samples/my-fixed100-s20261120 \
  --count 100 --seed 20261120 --workers 4
```

输入候选池非默认位置时显式传 `--input`。不要在同一输出目录用另一个
count/seed 重抽。存在失败时命令返回非零，这是保留异常位置的回执，不能
直接忽略后声称全部可运行。

生成目录：

```text
samples/my-fixed100-s20261120/
├── sample.json                 # 池、seed、数量与抽样策略
├── selection.jsonl             # 固定位置，含候选/advisory 恢复线索
├── download-report.json        # 各位置 complete/partial/error 及原因
├── download-history.jsonl
└── tasks/<task-id>/
    ├── task.json
    └── input/
        ├── src/                # 下载的 prefix，不预先应用补丁
        ├── fix.diff            # 所选候选补丁，若缺失则记录
        ├── meta.json           # 白名单重建的精简元数据
        └── manifest.json       # 字节数、SHA-256 与输入状态
```

`meta.json` 保留实例、仓库、漏洞描述、所选 candidate、真实 candidate ID、
来源和旧标签，而不是原样复制整个远端抓取上下文。`old_tags` 只是路由线索。
`alternate-candidates.json` 则在启动工作时由 `pipeline.run` 从 `selection.jsonl`
生成，**不是 S3 原始输入**。

只修复原位置的缺失/不完整下载，可对同一输出再次执行 `prepare` 并传
`--only <task-id或CVE> ...`。它会先验证缓存清单；缓存损坏不会静默重下载
冒充原始输入。`partial` 不是 `complete`，不能直接进入要求完整输入的调度；
但当前普通 `run`/`supervise` 尚未统一强制这一条件，详见第 4.1 节。

### 4.1 严格固定样本与 top-up 不可混用

固定位置实验要保留 `input_unavailable` 的原始错误，不用新实例补位。

只有明确要建立一个“完整输入的新样本”时，才使用：

```bash
.venv/bin/python -m pipeline.prepare \
  --output samples/my-complete100-topup \
  --top-up-from samples/my-fixed100-s20261120 \
  --count 100 --seed 20261120 --workers 4
```

它排除失败历史并补抽其他实例，已改变样本组成。历史写入
`download-history.jsonl`/`rejected-instances.jsonl`；不能拿它的成功率替代
原始固定样本的成功率。

### 4.2 全量数据准备（scale-up 入口）

`pipeline.prepare --all` 是给工程同学的一键全量入口：按冻结池原始顺序准备
全部 22,138 条可用输入，不做随机抽样，也不再需要 `--count/--seed`。

```bash
cd /nvme/wuyida/新管线开发

# 一键入口（推荐给工程同学；输出目录和 workers 可选）
scripts/prepare_full_pool.sh samples/full-20261109 30

# 等价的原生命令
.venv/bin/python -m pipeline.prepare \
  --input data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl \
  --output samples/full-20261109 \
  --all --workers 30
```

特性：

- 输出目录的 `sample.json.sampling_policy` 会写成 `all(frozen_pool_order)`；
- 已有全量 `selection.jsonl` 时只校验顺序并补齐缺失下载，可重复执行；
- `--all` 与 `--count` 互斥，也不能和 `--top-up-from` 混用；
- 仍可用 `--only <task-id或CVE>` 先修某几条，或用 `--sample-only` 只生成清单；
- 全量下载量很大（源码快照 + 补丁），运行前确认磁盘、S3 配额和 `--workers`
  （最大 30）。

> 全量模式只准备**分支无关的输入**。路由、SVC/FILE 分支判断仍在
> `pipeline.run`/`pipeline.supervise` 中进行，不在下载阶段预先分类。

## 5. 模型配置和运行前检查

默认模型环境文件是 `/nvme/wuyida/env`，可用 `--env-file` 指定其他安全路径。
它至少提供：

```text
ANTHROPIC_BASE_URL=<模型网关>
ANTHROPIC_AUTH_TOKEN=<密钥>   # 或 ANTHROPIC_API_KEY
```

不要将真实文件复制进文档。执行器固定为 Claude Code（`claude -p` 流式会话，
可用 `CLAUDE_BIN` 指定可执行文件），默认模型 `glm-5.3`；模型名必须与实际网关支持一致。

执行器给 Claude Code 设置：

```text
CLAUDE_CODE_MAX_CONTEXT_TOKENS=1000000
CLAUDE_CODE_AUTO_COMPACT_WINDOW=800000
CLAUDE_CODE_MAX_OUTPUT_TOKENS=65536
```

GLM-5.3 标准上下文是 1M；auto-compact 窗口留到 800k，避免贴着 1M 上限时
`messages + max_output_tokens` 超限导致 400。若实际网关只支持更小窗口，必须
按网关能力调低，否则会在请求层被拒绝，而不是在 Claude Code 里自动压缩。

环境预检会检查 Docker/Compose/buildx、模型网关和基础镜像：

```bash
.venv/bin/python -m pipeline.preflight \
  --env-file /安全路径/env \
  --output work/preflight-my-environment.json
```

准备共享的选手和 verifier 开发镜像：

```bash
.venv/bin/python -m pipeline.runtime_images
```

已存在的同名镜像默认复用；`--force` 会重建，使用前审查 tag 是否仍符合预期。
`runtime_images` 只是开发期准备，不能替代每题真实 target 的构建与验收。

## 6. 批量并发运行：统一入口

**先确认第 2 节的环境与隔离前提。** 运行入口只有一个：`pipeline.supervise`
统一并发调度；`pipeline.run` 是 supervisor 为单个 task 拉起的内部 worker，
不作为人工操作入口单独使用。下面命令会调用模型和 Docker；当前维护期间的
停机指令优先，不要因阅读 README 而自行启动正在暂停的样本。

```bash
cd /nvme/wuyida/新管线开发

.venv/bin/python -m pipeline.supervise \
  --sample samples/my-fixed100-s20261120 \
  --results results/my-batch-r1 \
  --env-file /安全路径/env \
  --batch-size 20 --concurrency 20 \
  --only <task-id-1> <task-id-2> # 从 selection.jsonl 取完整 ID，不用 shell 猜数补位
```

`--batch-size` 是新题名额上限，`--concurrency` 是本监督器 worker 上限；
携带恢复任务也共享并发额度，不能另开一批绕过限制。并发上限 40
（`--batch-size` 仍最多 30 个新题位；携带题另占额度）。
一个 results 目录只能属于一个样本，有 supervisor 锁，不能多个调度器
同时写同一目录。需要跨批迭代时，按第 6.3 节的 Agent 驱动流程直接启动
supervisor；没有协调器。

### 6.1 四阶段分别做什么

1. **路由**：读取输入证据，产生结构化 `route.json`，选择 SVC-EXPLOIT、
   FILE-EXPLOIT 或 FILE-POV。接受路由只是合成假设，不是通过。
2. **合成**：按路由分支创建真实 target、公开工作站、gold、oracle 和
   官方修复。原始 `input/` 不修改，恢复证据写入 `delivery/project/`。
3. **独立审查**：新会话读取冻结交付和合成轨迹，通过普通文件写入输出
   `review.json`；控制器校验其布尔 `passed` 和非空 `evidence`。
4. **验收**：冻结审查通过的交付，导出预构建镜像，用 Harbor 连续跑两次
   Agent 跑题；每次都由 verifier 在干净 vulnerable/patched 环境中做
   Pass2Fail，两次 reward 都是 1.0 才通过。

严格通过必须同时有：

```text
独立 review.passed = true
acceptance_runs 恰好 2 次
两次 acceptance_runs[].reward = 1.0
每次 verifier 内部：
  vulnerable.triggered = true，vulnerable.health.returncode = 0
  fixed.triggered = false，fixed.solution.returncode = 0，
  fixed.patched_health.returncode = 0
```

vulnerable 阶段的 exploit/PoV 正常 crash（134/1/124）不算协议失败；oracle
和 fixed 重建才是判定依据。第一次跑完后先按 `pristine-binds.tar` 恢复可写
bind，再跑第二次；第二次必须在这个恢复后的题包上仍然 Pass2Fail。这样测的是
“一次做题把题包写脏后能不能恢复干净”，而不是故意让第二次继承脏字节。

不要只看 `result.json.status=passed`、Harbor 进程无异常或容器启动成功。
详情见 [Harbor 验收设计](doc/Harbor验收设计.md)。

### 6.2 输出位置

```text
results/<run>/<task-id>/
├── result.json                 # 当前最终/失败状态
├── route/                      # 路由轨迹和结果
├── synthesis/                  # 合成轨迹和结果
├── review/                     # 独立审查轨迹
├── harbor/                     # 两次 Harbor Agent 验收、导出和 evidence
└── workspace/
    ├── input/                  # 只读输入副本与备用候选索引
    ├── route.json
    ├── review.json
    └── delivery/               # 接受审查的实际交付
```

`delivery/task.json` 由控制器在冻结前生成，agent 不手写：branch/host_type 来自
`route.json`，main/client 镜像来自公开 Compose，sidecar 由 Compose 服务列表
派生，healthcheck/oracle/solution 使用固定路径；FILE-POV 的 `public_runner`
写在 Compose 的 `client.x-public-runner`，runner 固定复用 `images.agent`。

每个 `route/`、`synthesis/`、`review/` 阶段都保留完整原始流和可读轨迹：

```text
stdout.jsonl        # Claude Code 原始 stream-json（完整，含 compaction 事件）
stderr.txt          # 子进程 stderr
cli-debug.log       # Claude Code 自己的 debug 日志（每题每阶段独立）
prompt.md           # 实际发送的初始 prompt（新运行；旧运行标注重建）
trajectory.jsonl    # 小索引：turn/工具名/字符数，供 supervisor 计数
tool-calls.jsonl    # 每次工具调用；每行第一个字段是北京时间
live.chat.md        # 完整 thinking/正文/工具调用/工具返回/压缩事件
sft.jsonl           # 结构化 messages，可直接用于 SFT
background/         # 后台任务 output 文件副本
background-tasks.jsonl  # 后台任务的 task_id/路径/归档位置
```

审查阶段读 `review-input/live.chat.md` 和 `review-input/tool-calls.jsonl`；
`trajectory.jsonl` 只做调度索引，不承载全文；`conversation.md` 已删除，
避免三份全文互相漂移。`tool-calls.jsonl` 里的 `description` 是 Claude Code
给 Bash 命令生成的短说明，不是 shell 输出，也不是题目描述。

**Autocompact 不会丢前面的轨迹**：`stdout.jsonl` 始终保留完整原始流；
`live.chat.md` 和 `sft.jsonl` 按时间顺序追加 `compact_boundary` /
`isCompactSummary` 事件，压缩前的 thinking、正文、工具调用和工具结果仍在。
旧轨迹可用 `.venv/bin/python -m pipeline.compact_logs <stage-dir>` 重新生成。

默认接受包发布到 `harbor_export/<YYYYMMDD>-production/`；不同 run 同日发布
必须注意冲突。生产应为每批显式指定不同的 `--published-root`，例如
`harbor_export/my-small-batch`。失败题不得因重试被发布。

导出题目名只保留公告 ID 和分支，不再带 `linux-014-` 前缀或 owner-repo：

```text
cve-2024-23346-file-pov
cve-2020-28483-svc-exploit-synthetic-host
```

后缀规则：SVC 用 `-svc-exploit-native-service` / `-svc-exploit-real-host` /
`-svc-exploit-synthetic-host`，FILE 用 `-file-exploit` / `-file-pov`。

导出名现在只保留公告 ID 和分支，例如 `cve-2020-28483-file-pov`；结果目录
在批次 terminal 后会由 supervisor 自动用同一规则整理，映射写入
`batch-NNN/renames.json`。内部 `result.json.task_id` 不变。只有 supervisor
崩溃导致未改名时，才需要手动补跑：

```bash
.venv/bin/python -m pipeline.rename_results results/<run>/batch-NNN
```
每个导出题目录里的 `acceptance.json` 是本次验收证据的只读副本
（两次 Harbor Agent run 的 reward 与 verifier evidence），不是运行依赖。

**镜像 tag 必须每题唯一。** 公开 Compose 的 `client` / `main` 镜像 tag 是
权威来源，控制器据此生成 `task.json.images.target` / `images.agent`，导出
只按这两个精确 tag 做 `docker save`，不会从容器或工作区猜镜像；复用
`:latest` 或跨题同名 tag 会让后构建的镜像覆盖前者，导出仍“成功”但内容错。
合成 Prompt 要求 tag 带 task id 或唯一 slug，并在所有修改完成后重新
build/tag；修改只存在于容器可写层时必须 `docker commit` 成这题最终 tag。

多容器 target 按公开 Compose 的**每个服务镜像**分别保存（client 进
`images/target.tar.gz`，sidecar 进 `images/<service>.tar.gz`）。`docker commit`
是单容器操作，不会自动提交整个 Compose 项目：每个可写层里有必需修改的容器
都要单独 commit 到自己的唯一 tag，并改对应服务的 `image`（client/main 改
公开 Compose；控制器再从 Compose 生成 `task.json.images.target` /
`images.agent`）。只 commit 但不更新引用的镜像不会被导出；卷内容也不会被
commit 带走。

卷和 bind 由管线单独封包，不依赖 commit：合成结束后、审查前，控制器把
named/anonymous volume 复制到 `delivery/environment/init/volumes/` 并把
Compose 改写为 `./` bind；导出时把所有可写 `./` bind 封进
`pristine-binds.tar`，差分 verifier 在每个 phase 前后还原。合成期间不要
`docker compose down -v` 删除卷数据。

### 6.3 批量迭代 skill（Agent 驱动）

`.cursor/skills/pipeline-iterate/SKILL.md` 是方法论，不是调度器：

- Agent 自己用 `pipeline.supervise` 启动每一批；
- 每 10 分钟用只读的 `scripts/report.py` 看每题成功/失败和剩余新题；
- Agent 自己分析失败、修管线、跑测试、决定携带和下一批。

没有 `iterate_batches` 协调器，没有 `start/approve/stop` 自动流程。

```bash
# 只读报告：当前结果 + 样本里还没用过的新题
python3 .cursor/skills/pipeline-iterate/scripts/report.py \
  --results results/<run> --sample samples/<batch>

# Agent 挑 30 道后，直接启动 supervisor
.venv/bin/python -m pipeline.supervise \
  --sample samples/<batch> \
  --results results/<run>/batch-001 \
  --batch-size 30 --concurrency 30 \
  --only <task-id-1> ... <task-id-30>
```

批次结束后 Agent 自己写 `doc/iteration-reports/<run>-batch-NNN.md`，修完
代码和测试后手动开下一批。细节见该 skill 的 `SKILL.md`。

### 6.4 交付后如何跑题 / 评测

发布目录（`pipeline.supervise --published-root` 指定的位置）是
`accepted_tasks_only` 的自包含交付包：

```text
<published>/
├── task_id_all.jsonl         # 每行 {"task_id": "..."}
├── bin/
│   ├── load_image.py         # 加载单题/全部镜像，并恢复可写 bind
│   ├── pass2fail_verifier.py # 通用 verifier 类
│   └── pristine_binds.py
├── shared-images/            # 多题共享的 agent/verifier 镜像
├── manifest.json
└── <task-id>/
    ├── image-lock.json       # role/ref/archive 镜像索引
    ├── images/               # 本题 target/sidecar/专用 agent 镜像
    ├── harbor-runtime-profile/
    │   ├── task.toml         # environment_mode=separate；不写 verifier import_path；不写超时
    │   ├── environment/      # 公开 main + client
    │   ├── pristine-binds.tar
    │   └── bin/              # 本题 profile 自带的通用 verifier + helpers
    └── acceptance.json
```

加载单题（镜像 + 预跑恢复）：

```bash
python3 <published>/bin/load_image.py --task <task-id>
```

`load_image.py` 会按 `image-lock.json` 加载 shared 和本题镜像，然后在返回前
调用 `pristine_binds.py` 恢复该题的 `harbor-runtime-profile/environment`。
这就是“做题前 wrapper”的预跑半边；如果要手动控制，可加 `--no-restore`。
加载全部共享镜像用 `--shared-only`；不带 `--task` 会加载 shared + 所有任务。

也可以让 `load_image.py` 直接包住一次跑题命令（前后各恢复一次）：

```bash
cd <published>/<task-id>/harbor-runtime-profile
PYTHONPATH="$PWD" python3 <published>/bin/load_image.py --task <task-id> \
  --run harbor run --path "$PWD" ... \
  --verifier bin.pass2fail_verifier:Pass2FailVerifier
```

跑一道题（新管线）：

```bash
cd <published>/<task-id>/harbor-runtime-profile
PYTHONPATH="$PWD" harbor run \
  --path "$PWD" \
  --agent <your-agent> \
  --n-attempts 1 --n-concurrent 1 \
  --jobs-dir <jobs> --job-name <unique-name> --yes \
  --verifier bin.pass2fail_verifier:Pass2FailVerifier
```

`task.toml` 不设置 agent/verifier/build 超时；超时和模型配置由 Harbor
`harbor_config.yaml` 或命令行控制，避免题目把外部评测的预算截断。

`exploit` 老管线的形式完全一样，只是模块名和 `PYTHONPATH` 指向不同：

```bash
cd <exploit>/runtime-profile
PYTHONPATH=<exploit-repo> harbor run \
  --path "$PWD" \
  --agent <your-agent> \
  --n-attempts 1 --n-concurrent 1 \
  --jobs-dir <jobs> --job-name <unique-name> --yes \
  --verifier orchestrator.export.separate.pass2fail_verifier:Pass2FailVerifier
```

共同点：

- `task.toml` 只声明 `environment_mode="separate"`，**不在 `[verifier]` 里写
  `import_path`**；
- verifier 是一个通用 `BaseVerifier` 类，由 `--verifier` 指定、由
  `PYTHONPATH` 让宿主 Python 找到；
- 同一宿主进程判多道题时，类只 import 一次；题目差异全部从
  `task_dir/tests/private/task.json` 和私有目录读取，不靠“每题一份 verifier 代码”。

判分语义：

- agent 没提交/没打中 → verifier 返回 reward 0，判分完成；
- 判分自身失败（target 起不来、oracle 异常、patch 无法应用等）→
  `fresh_verify` 抛 `VerifierInfraError`，不写 reward，Harbor 记 failed；
- `tests/test.sh` 只清空旧 reward，不再写占位 0；
- `Pass2FailVerifier.verify()` 结束时会恢复 public `environment` 的可写 bind，
  跑完题目不会把题包留在脏状态。

并发和重跑：

- **不同题目**可以并发：每题独立 `task_dir`、唯一镜像 tag、独立 Compose
  project 和 IPAM；`--job-name` 也必须唯一。
- **同一题目目录**不要并发：公开环境的可写 `./` bind 是同一份目录，两个
  player 会互相踩。需要同题并发时，每个 trial 复制一份
  `harbor-runtime-profile`。
- 重跑或上次崩溃后，先恢复可写 bind（`load_image.py --task` 已自动做）：

```bash
cd <published>/<task-id>/harbor-runtime-profile
PYTHONPATH="$PWD" python3 /path/to/<published>/bin/load_image.py --task <task-id> --root <published>
```

原因和三层恢复点见 [可写 Bind 恢复说明](doc/可写Bind恢复说明.md)。

> 2026-11-10 之前导出的 `harbor_export/*` 是旧格式（`_runtime/`、无
> `image-lock.json`/`task_id_all.jsonl`、`task.toml` 仍带超时、`test.sh`
> 仍写占位 0）。新管线导出已按第二版格式生成；旧 bundle 需要重新导出或
> 单独迁移后才能作为第二版交付物使用。

## 7. 失败边界、审查/验收续跑和历史证据

路由、合成和审查都使用普通文件写决定：`route.json`、`review.json`。
模型没有管线专用决策工具。字段缺失、格式错误、预算耗尽、合成主动写
`failure.json` 或 `reroute-request.json` 都会结束当前任务；控制器不自动改路由、
不重新合成，也不拼接 continuation/交接 Prompt。分支错误或失败题保留工作区
和轨迹，后续由人工回捞。

仅对已有冻结交付保留两种不重新合成的入口：

- `--review-delivery`：对已有交付重新独立审查。
- `--resume`：保留已批准交付，重跑验收，不调用合成修改交付。

复制这类已有交付到下一批时必须有 `carry-provenance.json` 和明确的
`carry-recovery.json`，实例身份一致；旧结果、轨迹、Harbor 证据和错误回执不得覆盖。
路由/合成恢复计划不会自动派发。

## 8. 跨批迭代（Agent 驱动）

没有协调器。每一批都是一个显式的 `pipeline.supervise` 调用，Agent 负责：

1. 用 `scripts/report.py --sample` 选出 30 道未使用的新题；
2. 在 `results/<run>/batch-NNN` 启动 supervisor，记录 PID 和日志；
3. 每 10 分钟看 `report.py`、`progress.json`、`supervisor.log`；
4. 批次结束后自己分析失败、修管线、跑测试、写批次报告；
5. 决定下一批：30 道新题 + review/harbor 类携带题。

携带规则：

- `review` / `harbor` 恢复：`--carry-results <old task dir...>`，要求旧任务有
  `workspace/route.json` 和完整的 `workspace/delivery`；
- `route` / `synthesis` 失败：不要用 `--carry-results`；在新批次里从样本
  输入重跑同一 task，当作 recovery，不算 fresh；
- 携带题共享并发额度，不另开 supervisor 绕过限制。

```bash
.venv/bin/python -m pipeline.supervise \
  --sample samples/<batch> \
  --results results/<run>/batch-002 \
  --batch-size 30 --concurrency 40 \
  --only <30 fresh ids> <carried ids> \
  --carry-results <old task dir 1> <old task dir 2>
```

停止某批时只 `kill` 该批 supervisor 的 PID；先核对完整命令行，不要
`pkill` 所有 python/claude。批次报告写在
`doc/iteration-reports/<run>-batch-NNN.md`，由 Agent 维护。

## 9. 当前已知工程化缺口

以下事项必须如实保留在交付风险中：

- 共享宿主 Docker 仅供开发，最终强隔离方案尚未在本管线实现。
- 缺少锁定的依赖清单、标准 worker 镜像与跨机器配置入口。
- 批协调器首 batch 是接管式接口，尚非通用从零生产 API；普通监督器也尚未
  统一强制 `manifest.status=complete`，scaling 前必须补齐入口校验。
- 路由、合成和分支纠错失败只保留证据供人工回捞，不再自动续跑；仅冻结交付
  的审查和 Harbor 基础设施验收有有界恢复。
- 2026-11-10 的离线单元回归为 100 项通过；这不代表真实模型、Docker 或生产
  端到端验收已通过，恢复生产前仍需审查变更并做受控小规模验证。
- 历史 gold 证据严格门禁仍需在恢复生产前完成复核。
- 只有实际证据满足严格验收的题目才能发布和计数；fixture、候选数量、
  路由接受率与旧发布记录都不能冒充生产通过率。

## 10. 相关文档

- [输入下载与预处理](doc/输入下载与预处理.md)：S3 对象、字段白名单、缓存、
  状态与 `alternate-candidates.json` 的详细解释。
- [Prompt 索引与原文](doc/pipeline-prompts.md)：路由、通用合成、分支指南与审查。
- [SVC-EXPLOIT 分支全流程详解](doc/SVC-EXPLOIT分支全流程详解.md)：从原始数据到 Harbor 导出。
- [FILE-EXPLOIT 分支全流程详解](doc/FILE-EXPLOIT分支全流程详解.md)：单文件未授权效果题的完整流程。
- [FILE-POV 分支全流程详解](doc/FILE-POV分支全流程详解.md)：单文件 PoV、固定 runner 与精确 oracle。
- [main 与 runner 镜像说明](doc/main与runner镜像说明.md)：main 镜像怎么选、runner 为什么独立、solution.sh 内的离线 build/replace。
- [审查阶段可见内容与边界](doc/审查阶段可见内容与边界.md)：reviewer 能看到什么、三个分支检查重点、只读边界。
- [Harbor 验收设计（两次 Agent 跑题）](doc/Harbor验收设计.md)：当前验收逻辑、两次运行、可写文件污染检测、结果字段、交付后如何跑题。
- [可写 Bind 恢复说明](doc/可写Bind恢复说明.md)：为什么恢复、`pristine-binds.tar`、wrapper、三层恢复点和边界。
- [文档索引](doc/README.md)：完整文档目录；旧版设计与开发交接已归档或移除。
- [交付格式](docs/reference/交付格式.md)：Harbor 题包格式参考。
