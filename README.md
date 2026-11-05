# 新管线开发交接说明

> 更新日期：2026-11-03。本目录包含当前规划、原始输入、候选清单、筛选脚本和抽样审查。
>
> **当前已实现轻量四阶段管线，并跑通首个 Janet 题目的真实 Harbor 0.22.0 验收。**100 题固定随机样本已建立，80 条源码输入完整，20 条上游输入异常已记录；尚未完成 100 题批量试产，不能将单题通过当作批量成功率。

## 1. 一句话说明任务

利用旧 Web 管线未选用的 **38,901 个漏洞 × 仓库实例**，合成真实可验证的 Linux 用户态漏洞环境：能做网络服务高阶利用就做 `SVC-EXPLOIT`，否则做 `FILE/BIN`，其中高阶利用优先、PoV 兜底，最终统一交付 Harbor 题包。

老管线是 `exploit-from-git`，已选 **13,173 条普通 Web 应用实例**；新管线不重复批量制造普通 CMS/业务 Web 题，而处理服务、可宿主化组件和单文件目标。

## 2. 先读哪些文件

1. **[完整实施计划](doc/Linux用户态漏洞利用新管线计划.md)**：分支定义、排除范围、四阶段流程、Harbor 验收和数量口径。
2. **[Harbor 交付格式](docs/reference/交付格式.md)**：最终题包的目录、镜像、配置与运行要求。
3. **[全池随机 50 条审查](work/remaining_38901_random50_audit.json)**：理解剩余数据的实际构成。
4. **[28 条排除项中文说明](work/remaining_38901_random50_exclusions_zh.md)**：理解为什么有些 CVE 不能硬套到当前分支。
5. **[SVC 随机 50 条审查](work/svc_exploit_recall_random50_audit.json)**：理解服务候选池的真实噪声。

飞书旧页面：<https://aicarrier.feishu.cn/wiki/UnB4wnwLDiV6MJku1HtcduZ3nfd>。**本地 Markdown 比飞书更新，后续以本地计划为准。**

## 3. 已确认的核心原则

### 3.1 三个交付分支

| 分支 | 选手入口 | 合格结果 |
| --- | --- | --- |
| `SVC-EXPLOIT` | 真实网络协议或官方客户端访问服务/宿主 | 未授权执行、读取、写入、认证绕过、SSRF 或有严格对照的服务 DoS |
| `FILE-EXPLOIT` | 一个文件，固定 runner，真实 release 目标 | 未授权代码执行、受保护数据读取等，不接受 crash-only |
| `FILE-POV` | 一个文件，固定 runner | vulnerable 触发目标 sanitizer/运行时/资源效果，fixed 不触发，良性正常 |

SVC 的宿主可为原生 daemon、真实应用宿主或审计通过的薄宿主。**不是库就直接排除，也不是给文件解析器随便套 HTTP 就算 SVC。**

### 3.2 四阶段，不做复杂状态机

1. **路由准入**：Agent 判断抛弃或选择一个分支，写 `route.json`；调度器只按该文件路由。
2. **分支合成**：不同分支使用不同 prompt、产物、test/verifier，保存完整合成轨迹。
3. **独立审查**：新 session 输入轨迹与产物，检查伪造、hack、泄漏、错误分支和证据真实性。
4. **Harbor 验收**：导出镜像与题包，执行对应 `tests/test.sh`/verifier，用 Harbor 0.22.0 做真实终验。

使用通用 shell、文件编辑、编译器、容器 CLI、公开网络工具和 Python/Shell。**不设计专属 MCP 工具，不复制老管线多阶段状态机、阶段产物矩阵和 MVP 工具。**合成轨迹后续要用于通用 SFT。

### 3.3 统一验收底线

- 正常输入/请求和健康检查通过；
- gold 在干净 vulnerable 环境成功；
- 同一 gold 在干净 fixed 环境失败，fixed 健康；
- 从最终交付包重复验证，结果稳定且归因于目标漏洞；
- fixed、gold 和私有裁判不能泄漏给选手。

可以用固定 secret、固定配置，不额外设计动态 nonce。参考 verifier 只用于理解 vulnerable/fixed 两轮验证思想，不要求复用其复杂编排。

## 4. 数据与候选口径

### 4.1 原始输入已放进本目录

`data/raw/` 中的文件为原样复制：

| 文件 | 行数 | 用途 |
| --- | ---: | --- |
| `catalog.instances.jsonl` | **52,074** | 完整“漏洞 × 仓库”实例，含 CVE、仓库、修复候选、引用和 PoC 线索 |
| `meta.exploit.g0.jsonl` | **13,173** | 老 Web 管线已选题单，用规范化 `instance_id` 排除 |
| `catalog.tagged_instances.g0.jsonl` | **52,074** | 旧标签，仅作召回/排序线索，不作新管线硬准入 |

旧标签里的 `P0–PX`、`g0_keep`、`poc_available`、`surface=local_file`、C/C++ 等都可能误杀，不可直接当新管线真值。

### 4.2 派生数据

| 文件 | 数量 | 含义 |
| --- | ---: | --- |
| `data/remaining-38901.instances.jsonl` | 38,901 | 原始全集扣除旧 Web 题单后的完整剩余池，附 `old_tags` |
| `data/file-pov-g1.candidates.jsonl` | 13,956 | 非 kernel overflow/DoS 高召回，含 C/C++ 之外的语言 |
| `data/bin-file-exploit-g1.candidates.jsonl` | 8,372 | 上述池中具有内存破坏线索、优先尝试高阶利用的子集 |
| `data/svc-exploit.recall-candidates.jsonl` | 13,076 | 按新 SVC/宿主定义生成的宽召回池 |
| `data/candidate-report.json` | — | FILE/BIN 候选的语言、标签等统计 |
| `data/svc-exploit.recall-report.json` | — | SVC 候选召回原因与统计 |

**所有候选都是元数据线索，不是已准入、已构建或可交付题目。**路由前不同池可重叠；路由后一个实例只进一个分支，至多产出一道题。

本目录包含完整元数据，但**不包含所有实例的源码快照**。阶段一/二 Agent 需根据仓库、提交和引用自行恢复 vulnerable/fixed 源码与所需材料。

### 4.3 如何正确理解数量

- 全池随机 50 条静态审查：9 条初步 SVC、9 条初步 FILE-POV、4 条待定、28 条排除。
- `18/50 × 38,901 ≈ 14,004` 只是**全池可能进入分支评估的粗略外推**，不是交付量。
- SVC 候选池另一组 50 条：14 条明确符合、3 条待定、33 条不符合；`17/50 × 13,076 ≈ 4,446` 只是 **SVC 宽候选估算**，两组样本不能混用。
- 真正数量必须由 100 道完整四阶段试产的通过率决定，并扣除普通 Web 重复、错误仓库、无法构建、无法恢复 gold、审查与 Harbor 失败。

## 5. 目录结构

```text
新管线开发/
├── README.md                         # 本交接说明
├── doc/
│   └── Linux用户态漏洞利用新管线计划.md  # 最新完整计划
├── data/
│   ├── raw/                          # 原始全集、旧题单、旧标签
│   ├── remaining-38901.instances.jsonl
│   ├── file-pov-g1.candidates.jsonl
│   ├── bin-file-exploit-g1.candidates.jsonl
│   ├── svc-exploit.recall-candidates.jsonl
│   └── *report.json
├── scripts/
│   ├── export_remaining_and_service_scan.py
│   ├── select_two_route_candidates.py
│   ├── select_svc_exploit_candidates.py
│   └── publish_plan_to_feishu.py     # 可选发布工具，与合成无关
├── work/                             # 抽样与人工/Agent静态审查证据
├── docs/reference/交付格式.md
└── reference/pass2fail_verifier.py   # 老管线参考实现
```

## 6. 复现候选清单

只需 Python 3 标准库，在**本目录**运行：

```bash
# 重建剩余全集与旧版服务线索池；旧服务池只作历史对照
python3 scripts/export_remaining_and_service_scan.py

# 重建 FILE/BIN 两个高召回池
python3 scripts/select_two_route_candidates.py

# 重建当前 SVC 候选池和固定随机种子的50条样本
python3 scripts/select_svc_exploit_candidates.py
```

注意：前两个脚本会重写 `data/` 中同名派生文件；`raw/` 原始数据不会被修改。脚本报告中的路径按执行环境生成，不代表额外数据依赖。

`work/` 中：

- `remaining_38901_random50*`：全池 50 条审查，随机种子 `20261103`；
- `svc_exploit_recall_random50*`：当前 SVC 池 50 条审查；
- `service_scan_random50*`：旧版 16,418 条原生服务定义审查，**不要与当前 SVC 定义混用**；
- `file_pov_100_samples.jsonl`、`review_samples.jsonl`：早期分层审查材料，仅供证据参考，不是当前最终路由结果。

## 7. 接手后的具体工作

1. 从剩余池随机抽取 **100 道**，固定样本与随机种子，直接开始完整流程，不先挑简单题。
2. 实现轻量调度器：阶段一读写 `route.json`，根据分支选择 prompt；只保留日志和失败原因，不建复杂状态机。
3. 分别实现三个分支的合成 prompt、最小环境/gold 模板和 verifier。
4. 实现独立 review session，确保输入包含合成轨迹和实际产物，并输出可追踪的审查证据。
5. 实现镜像归档和 Harbor 导出，真实跑通 vulnerable 成功、fixed 失败、良性健康及交付包终验。
6. 记录每条实例的路由、合成、审查、Harbor 结果与成本；按实际通过率决定是否扩产。
7. 最终提供分布清单：三个分支数量；SVC 的宿主类型；漏洞类型、语言和验收方式。只统计通过独立审查与 Harbor 验收的题。

## 8. 当前实现与已实测结果

### 8.1 运行入口

在 `/nvme/wuyida/新管线开发` 执行。模型凭据仅从 `/nvme/wuyida/env` 读取，不写入题目、日志或镜像。

```bash
# 固定种子抽样；后续重复执行只校验缓存，并记录上游缺失/损坏。
python3 -m pipeline.prepare --output samples/pilot100-20261103 --workers 4

# 保留80条完整原始输入，排除原始失败实例后继续固定随机补样到100条。
python3 -m pipeline.prepare --output samples/pilot100-usable-20261103 \
  --top-up-from samples/pilot100-20261103 --count 100 --workers 4

# 首次从本机 apt 代理准备 ubuntu:22.04；已有镜像时直接复用。
python3 -m pipeline.bootstrap_image

# 单题：路由 -> GLM-5.3 分支合成 -> 新会话独立审查 -> 最终Harbor验收。
python3 -m pipeline.run --sample samples/pilot100-20261103 \
  --results results/pilot100-v1 --only CVE-2026-10267

# 中断后保留 input/ 和 delivery/，用新 session 继续；不要重跑路由或清空构建产物。
python3 -m pipeline.run --sample samples/pilot100-20261103 \
  --results results/<new-run> --only <CVE-ID> --retry-synthesis --continue-synthesis \
  --route-from results/<old-run>/<task-id>/workspace/route.json \
  --workspace-from results/<old-run>/<task-id>/workspace

# 只导出通过审查和差分验证的题；默认公开包不含 gold。
python3 -m pipeline.harbor --results results/janet-synthesis-v2 \
  --output harbor_export/janet

# --oracle 另外生成隔离的验收配置；不可将该配置作为玩家题包发布。
python3 -m pipeline.harbor --results results/janet-synthesis-v2 \
  --output harbor_export/janet --oracle
sg docker -c 'exec .venv/bin/harbor run \
  --path harbor_export/janet/<task-id>/harbor-oracle-profile \
  --agent oracle --n-attempts 1 --n-concurrent 1 \
  --jobs-dir harbor_jobs --job-name <unique-job-name> --yes'
```

`--concurrency` 控制题级并发，但 Docker 构建/差分验证串行执行，避免相互污染。默认模型为 `glm-5.3`，执行器为原生 Anthropic 工具循环。

### 8.2 输入和交付边界

- 抽样从 38,901 条剩余实例固定抽取 100 条，种子 `20261103`；S3 只拉选中实例的 prefix 与 `fix.diff`，不因坏数据换简单题。
- 缓存输入由 `manifest.json` 校验；失败的实例保留原因。源码快照不完整时允许从对应官方 revision 补齐，但不能换仓库或伪造基线。
- 每个阶段保存 `result.json` 与轨迹，合成工具输出单独保存；审查可读取合成轨迹、工具日志、gold 和实际执行报告。
- 合成 Agent 只做自检；总控不在中间运行完整 verify。独立审查通过后冻结全部交付文件哈希，最终 Harbor 阶段从冻结副本完成私有差分，并对导出的真实题包运行 gold（1.0）与空提交（0.0）。
- 差分报告必须满足：构建成功、良性输入正常、gold 在 vulnerable 成功、gold 在 fixed 不触发且 fixed 健康。
- 公开交付只含漏洞工作站/服务、指令和公开评分器；gold、fixed 和私有 verifier 只在工厂侧。`harbor-oracle-profile` 是显式隔离的验收入口。

### 8.3 Harbor 0.22.0 实测约束

- `[environment].docker_image` 必须声明预构建主服务镜像；任务 Compose 的 `main.image` 在导出时移除，避免覆盖 Harbor 注入的 Agent 镜像。
- 本机不支持 Harbor 的 `no-network` egress 内核探测，默认配置使用 `public`；任务本身不需要外网，交付镜像包含全部运行依赖。
- `/logs/verifier/reward.json` 只允许数值 reward 字段。导出器将原始详细评分移至 `evidence.json`，最终只写 `{"reward": 0.0 或 1.0}`。
- 不用 `sh` 强行执行带 `pipefail` 的 Bash 测试；保留测试脚本的 shebang。
- `docker load` 成功不等于 Harbor 验收成功，必须实际执行 `harbor run` 并检查 trial 的 `verifier_result` 与 `exception_info`。

### 8.4 已完成的端到端样例

Janet `CVE-2026-10267` 路由为 `FILE-POV`。独立审查通过；gold 的 42 字节 marshalled image 在 vulnerable 触发 `doframe` 的 ASAN heap-buffer-overflow，fixed 在 unmarshal 阶段拒绝，良性 image 正常执行。冷构建和冻结复验均通过。

最终使用真实 Harbor 0.22.0 `oracle` 运行：**1 trial、0 exception、reward=1.0**。空提交反例为 **reward=0.0**。报告见 `results/janet-synthesis-v2/`、`harbor_jobs/janet-harbor-oracle-v5/`。

tcpdump `CVE-2017-13048` 已确认 RSVP Fast Re-Route 的 vulnerable/fixed ASAN 差分，正在完成交付与独立审查。100 题完整通过率尚未测量。

## 9. 不应踩的坑

- 把正则召回数、静态审查比例或 100% 转化假设说成产量；
- 把“本地文件 crash”包装成高阶 exploit；
- 给任意本地库套 HTTP 后声称是真实原生网络服务；
- 把客户端被恶意服务端攻击改写成服务端漏洞；
- 将普通 Web/XSS/CSRF 题重新量产，或与老管线重复；
- 忽略 CVE—仓库—版本—补丁错配；
- 让固定 runner 改变真实 API 语义，或制造漏洞/旁路来通过裁判；
- 用工厂内部 Python 自检替代最终 Harbor 运行；
- 在合成或选手轨迹中引入专属 MCP 工具、私有路径、fixed/gold/私有裁判。
