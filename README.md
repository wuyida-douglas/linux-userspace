# Linux 用户态漏洞题目管线使用说明

把固定漏洞候选池中的 **CVE × 仓库 × 修复候选** 变成可审计的 Harbor 题包。
主流程是：固定抽样（或全量）→ 定点 S3 下载与校验 → 路由 → 分支合成 →
独立审查 → Harbor gold/null 与最终 bundle 差分验收。

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

默认文件：

```text
results/label-production-v1/candidates-kept.jsonl
```

`pipeline.prepare` 在 S3 调用之前强制验证：

- 23,873 个唯一 `instance_id`；
- 每行 `metadata_label.label == keep`；
- 文件 SHA-256 为
  `1d9bdbd09a55a84fee01bd5ccf19027e0db2b8e1da37c91eaa653565c2c36142`。

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
  --input results/label-production-v1/candidates-kept.jsonl \
  --output samples/my-fixed100-s20261120 \
  --count 100 --seed 20261120 --sample-only

# 下载并预处理同一固定样本；workers 仅控制下载并发，最大 30。
.venv/bin/python -m pipeline.prepare \
  --input results/label-production-v1/candidates-kept.jsonl \
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
全部 23,873 条输入，不做随机抽样，也不再需要 `--count/--seed`。

```bash
cd /nvme/wuyida/新管线开发

# 一键入口（推荐给工程同学；输出目录和 workers 可选）
scripts/prepare_full_pool.sh samples/full-20261109 30

# 等价的原生命令
.venv/bin/python -m pipeline.prepare \
  --input results/label-production-v1/candidates-kept.jsonl \
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
携带恢复任务也共享并发额度，不能另开一批绕过限制。两者最大 30。
一个 results 目录只能属于一个样本，有 supervisor 锁，不能多个调度器
同时写同一目录。需要严格固定样本配额时，使用第 8 节的
`pipeline.iterate_batches` 协调器，它内部同样调用 supervisor。

### 6.1 四阶段分别做什么

1. **路由**：读取输入证据，产生结构化 `route.json`，选择 SVC-EXPLOIT、
   FILE-EXPLOIT 或 FILE-POV。接受路由只是合成假设，不是通过。
2. **合成**：按路由分支创建真实 target、公开工作站、gold、oracle 和
   官方修复。原始 `input/` 不修改，恢复证据写入 `delivery/project/`。
3. **独立审查**：新会话读取冻结交付和合成轨迹，通过普通文件写入输出
   `review.json`；控制器校验其布尔 `passed`、findings 和执行检查字段。
4. **验收**：冻结审查通过的交付，导出预构建镜像，执行 Harbor gold、null
   以及最终 bundle 的 vulnerable/fixed 差分。

严格通过必须同时有：

```text
独立 review.passed = true
Harbor gold.reward = 1.0
Harbor null.reward = 0.0
最终 bundle differential.status = passed
最终 bundle differential.report.success = true
```

不要只看 `result.json.status=passed`、Harbor 进程无异常或容器启动成功。
详情见 [Harbor 交付与差分验证设计](doc/统一Harbor交付与差分验证设计.md)。

### 6.2 输出位置

```text
results/<run>/<task-id>/
├── result.json                 # 当前最终/失败状态
├── route/                      # 路由轨迹和结果
├── synthesis/                  # 合成轨迹和结果
├── review/                     # 独立审查轨迹
├── harbor/                     # gold/null、导出和差分证据
└── workspace/
    ├── input/                  # 只读输入副本与备用候选索引
    ├── route.json
    ├── review.json
    └── delivery/               # 接受审查的实际交付
```

默认接受包发布到 `harbor_export/<YYYYMMDD>-production/`；不同 run 同日发布
必须注意冲突。生产应为每批显式指定不同的 `--published-root`，例如
`harbor_export/my-small-batch`。失败题不得因重试被发布。

导出题目名会把完整仓库 URL 从内部 `task-id` 里去掉，并在末尾追加分支：

```text
linux-014-cve-2024-23346-materialsproject-pymatgen-file-pov
linux-001-cve-2020-28483-gin-gonic-gin-svc-exploit-synthetic-host
```

后缀规则：SVC 用 `-svc-exploit-native-service` / `-svc-exploit-real-host` /
`-svc-exploit-synthetic-host`，FILE 用 `-file-exploit` / `-file-pov`。
每个导出题目录里的 `acceptance.json` 是本次验收证据的只读副本（Harbor
gold/null 与最终 bundle 差分），不是运行依赖。

**镜像 tag 必须每题唯一。** 导出只按该题 `task.json` 的 `images.target` /
`images.agent` 精确 tag 做 `docker save`，不会从容器或工作区猜镜像；复用
`:latest` 或跨题同名 tag 会让后构建的镜像覆盖前者，导出仍“成功”但内容错。
合成 Prompt 要求 tag 带 task id 或唯一 slug，并在所有修改完成后重新
build/tag；修改只存在于容器可写层时必须 `docker commit` 成这题最终 tag。

多容器 target 按公开 Compose 的**每个服务镜像**分别保存（client 进
`images/target.tar.gz`，sidecar 进 `images/<service>.tar.gz`）。`docker commit`
是单容器操作，不会自动提交整个 Compose 项目：每个可写层里有必需修改的容器
都要单独 commit 到自己的唯一 tag，并改对应服务的 `image`；卷内容不会被
commit 带走。

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

## 8. 批次协调器与 scaling 操作

`pipeline.iterate_batches` 在 `pipeline.supervise` 之上负责：固定批次选择、
监控、逐批归因、人工代码修复复核门禁、把明确的管线恢复任务带入下一批。
它不是简单“失败后无限重启”的循环。

每批结束生成 `batch-NNN-audit.json`。下一批前必须检查轨迹与代码缺陷，并把
该审计的 `code_fix_review.approved` 设为 `true`；这是一项**人工/独立代码
复核门禁**，不是自动测试或模型自批。严格验收数量要按第 6.1 节逐项统计。

新生产建议先用第 6 节的显式题单监督器完成受控批次，再按审计结果编排
下一批。`iterate_batches` 当前的 `number == 1` 路径需要接管已有的
initial-results 和 initial supervisor，不是通用的从零启动接口：

```text
--sample <固定样本>
--output <协调器状态目录>
--initial-results <第一批结果目录>
--initial-supervisor-pid <当前第一批监督器 PID，无存活接管场景时不能乱填>
--initial-only <第一批固定 fresh ID...>
--initial-observed-only <已观察且禁止新派遣的旧位置...>
--batch-size 20 --concurrency 20 --target-size 100
--preserve-unavailable-inputs
```

只有在接管现有生产时才传 `initial-carried-root`/`initial-carried` 等历史参数。
**不要把当前一次实验的 PID、carry 列表或 selection 复制到新样本。** 工程
scaling 前应把“从零新建第一批”和“接管既有第一批”拆成明确、独立的命令，
并给批次完成、失败、停机和人工审批定义标准自动化接口。

## 9. 当前已知工程化缺口

以下事项必须如实保留在交付风险中：

- 共享宿主 Docker 仅供开发，最终强隔离方案尚未在本管线实现。
- 缺少锁定的依赖清单、标准 worker 镜像与跨机器配置入口。
- 批协调器首 batch 是接管式接口，尚非通用从零生产 API；普通监督器也尚未
  统一强制 `manifest.status=complete`，scaling 前必须补齐入口校验。
- 路由、合成和分支纠错失败只保留证据供人工回捞，不再自动续跑；仅冻结交付
  的审查和 Harbor 基础设施验收有有界恢复。
- 2026-11-09 的离线单元回归为 102 项通过；这不代表真实模型、Docker 或生产
  端到端验收已通过，恢复生产前仍需审查变更并做受控小规模验证。
- 历史 gold 证据严格门禁仍需在恢复生产前完成复核。
- 只有实际证据满足严格验收的题目才能发布和计数；fixture、候选数量、
  路由接受率与旧发布记录都不能冒充生产通过率。

## 10. 相关文档

- [输入下载与预处理](doc/输入下载与预处理.md)：S3 对象、字段白名单、缓存、
  状态与 `alternate-candidates.json` 的详细解释。
- [Prompt 索引与原文](doc/pipeline-prompts.md)：路由、通用合成、分支指南与审查。
- [Harbor 交付与差分验证设计](doc/统一Harbor交付与差分验证设计.md)：交付和验收边界。
- [开发交接](doc/管线开发交接.md)：历史开发状态；其中带日期的结果不是当前
  生产完成度证明。
- [交付格式](docs/reference/交付格式.md)：Harbor 题包格式参考。
