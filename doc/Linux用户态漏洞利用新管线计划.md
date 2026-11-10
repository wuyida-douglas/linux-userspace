# Linux 用户态可容器化漏洞利用新管线计划

> **历史计划（2026-11-03）**：当前实现与验收以根目录 `README.md`、
> [Harbor验收设计](Harbor验收设计.md)、[交付合同与健康检查设计](交付合同与健康检查设计.md)
> 和 [main与runner镜像说明](main与runner镜像说明.md) 为准；本文只保留早期设计背景。

> 2026-11-03。本文是当前唯一实施计划，替代《新管线两条路线与候选》。目标是批量构造真实、可验证、适配 Harbor 的漏洞利用环境，并保留可迁移到通用 harness 的合成轨迹。
>
> **高阶效果优先，PoV 兜底；真实性优先于题型包装和数量。**

## 1. 先纠正分类

此前的 `FILE-POV-G1` 与 `BIN-FILE-EXPLOIT-G1` 不是两条独立路线，而是 **FILE/BIN 同一交互契约下的两个验收等级**。高阶池是 PoV 池的子集，最终同一实例只保留最高达成等级，不重复计数。

新的生产结构是：

```text
Linux 用户态可容器化漏洞利用（总类）
│
├── SVC-EXPLOIT：服务/宿主的网络入口，高阶效果裁判
│   ├── native_service：原产品真实 daemon/数据库/网络服务
│   ├── real_host：真实应用调用受影响库，库只是漏洞组件
│   └── synthetic_host：工厂薄宿主，必须满足真实性与可达性审计
│
└── FILE/BIN：单文件、一次性进程
    ├── FILE-EXPLOIT：未授权执行、受保护数据读取等高阶效果
    └── FILE-POV：sanitizer/运行时错误或资源型 DoS 差分
```

**“原生网络服务”只对应 `native_service`，不能作为整个新管线的名称。**整个计划称为 **Linux 用户态可容器化漏洞利用**，英文为 **Containerizable Linux Userspace Vulnerability Exploitation**。

**用户态**就是漏洞位于普通应用程序中，由 Linux 内核按普通进程权限运行，而不是位于内核、驱动或虚拟机管理层；本地解析器和网络 daemon 都可以是用户态程序。

Mining 与 exploitation 按任务目标划分：发现/定位/证明漏洞偏 mining；把漏洞转化为安全影响偏 exploitation。源码、补丁和调试器是独立的信息面配置，不是分类边界。PoV 侧重触发和复现，高阶 exploit 侧重未授权效果。

## 2. 现阶段排除什么，为什么

### 2.1 直接排除的运行环境

| 排除项 | 原因 |
| --- | --- |
| Linux kernel、驱动、内核网络协议栈 | 需要特定内核、QEMU/VM、内核构建与裁判，不能复用用户态 Docker 管线 |
| hypervisor、真实容器/虚拟机逃逸、嵌套虚拟化 | 依赖宿主权限、KVM/嵌套虚拟化，环境与安全边界复杂 |
| 浏览器引擎、V8/JSC、XSS/CSRF 等受害者交互 | 需要渲染页面、模拟受害者操作或检查浏览器内部状态，普通网络/文件入口和现有裁判覆盖不了 |
| Windows GUI/NTFS、移动端、专用硬件、固件/IoT | Linux OCI 无法原生复现，需要仿真或专用平台 |
| 需要 GPU、USB、TEE、真实设备或特定宿主状态 | 当前 worker 与交付环境无法保证可复现 |
| 纯客户端/恶意服务端攻击客户端 | 攻击角色与 `SVC-EXPLOIT` 相反；若做客户端题必须另建 CLIENT 契约，本期不做 |

这里的排除是**本管线边界**，不是漏洞价值判断。浏览器进程技术上也是用户态，但交互和裁判不同，所以仍排除。

### 2.2 普通 Web 的分工

老管线只选取了其中 **13,173 个普通 Web 应用实例**；剩余的 38,901 条主要属于非 Web、非 HTTP 或文件输入形态，不适合直接套老管线，本期为它们选择 SVC 或 FILE/BIN 分支，而不是重复制作普通 CMS/业务 Web 题。

### 2.3 元数据与可复现性排除

- CVE、仓库、受影响版本、修复提交无法对齐；
- 无法恢复可运行的 vulnerable/fixed，或无法获得/生成合法 gold；
- 普通错误、无关 crash、人工制造的漏洞或裁判捷径；
- 没有真实可达的不可信输入路径；
- 必须依赖工厂专属工具、在线状态或不可交付的宿主服务才能运行。

## 3. 输入数据与筛选规则

### 3.1 输入全集

- **38,901 个剩余“漏洞 × 仓库”实例**：`新管线开发/data/remaining-38901.instances.jsonl`。
- 每条含 CVE/描述/版本/引用/PoC 线索、代码仓库与修复候选，并附 `old_tags`。
- 原始输入：`data/raw/catalog.instances.jsonl`、`catalog.tagged_instances.g0.jsonl`、`meta.exploit.g0.jsonl`，均已纳入本交接目录。
- 本目录包含完整元数据，但不包含全部题目源码快照。源码由阶段一/二 Agent 按仓库与提交恢复；历史本地快照仅含部分实例，且有别名/多来源，不代表全部实例已恢复源码。

### 3.2 先高召回，再硬准入

元数据阶段不按旧 P0–PX、`g0_keep`、`poc_available`、C/C++ 或 `local_file` 硬过滤。这些字段只作排序线索，避免误杀库、真实宿主和误标 CLI。

已有线索池：

- FILE/BIN overflow/DoS 高召回：**13,956 条**；
- 其中内存破坏高阶方向：**8,372 条**；
- 当前 SVC 宽召回：**13,076 条**；只使用标题、描述、产品/仓库身份和旧标签证据，不再用引用链接本身命中。按当前 SVC/宿主定义对随机 50 条做多 Agent 静态审查，**14 条明确符合、3 条待定、33 条不符合**，明确候选准确率约 **28%**，符合加待定约 **34%**。这不是构建、利用或交付转化率。

不同线索池可重叠，不能相加为产量。

### 3.3 统一的硬准入条件

1. Linux 用户态、可容器化、满足上述排除规则；
2. CVE—仓库—版本—补丁一致；
3. 能说明“不可信输入 → 真实入口/宿主 → 漏洞组件 → 可观察结果”；
4. 能构建 vulnerable 与 fixed，并恢复正常功能；
5. 有确定性 oracle，能区分指定漏洞、普通错误和无关漏洞；
6. 最终能以 Harbor 题包交付。

先验证入口和 oracle，再投入构建与利用开发。没有 oracle 的 CVE 不进入量产。

## 4. 分支选择：不是按“库/服务”机械分类

### 4.1 第一优先级：SVC-EXPLOIT

**选手通过真实网络协议或官方客户端与运行中的目标交互，必须产生服务端/目标侧未授权效果。**服务化不是目的；它必须保留漏洞的真实输入语义和安全边界。

#### native_service

原产品就是 daemon、数据库、消息队列、VPN、DNS、SSH、SMTP、代理等。使用原产品监听接口、配置和客户端。

#### real_host

真实应用调用受影响库，例如真实文件处理应用调用 ImageMagick。攻击请求沿真实产品调用链到达库漏洞，结果发生在目标侧。

#### synthetic_host

没有合适真实宿主时，允许工厂写薄服务调用公开 API。它不是禁止项，但必须通过：

1. 使用真实公开 API、默认或文档支持的调用方式，不修改漏洞代码；
2. 不人为降低校验、不额外暴露危险管理接口、不直接提供答案；
3. 输入能到达指定漏洞路径，正常请求和 fixed 负控成立；
4. 服务化确实增加需要考查的安全能力，例如权限、状态、会话、网络边界；若只是给文件解析器套 HTTP 外壳而没有新增能力，优先 FILE/BIN；
5. 元数据明确标记 `host_type=synthetic_host`，不冒充上游原生服务。

libssh、SQLite、DNS 解析库、执行 SSH 操作的库都**不因“是库”直接排除**。关键是选择何种真实角色：目标服务端、真实应用宿主、薄宿主，或单文件目标。客户端漏洞不能反包装成服务端漏洞。

#### SVC 的效果裁判

执行 canary、受保护 secret 读取、文件/数据库 landing、认证后高权限 secret、目标侧 SSRF 回连，或有严格健康对照的服务 DoS。HTTP 500、端口开放、普通连接成功不算利用。

### 4.2 第二优先级：FILE/BIN

**SVC 是 service（服务）的缩写，表示选手通过运行中的网络服务与目标交互。**例如图片解析库中的缓冲区溢出，如果真实输入只是一个图片文件，就给固定解析器提交图片走 FILE/BIN；只有存在真实或合理的宿主服务、攻击者通过网络提交图片时，才走 SVC-EXPLOIT。

不适合服务化，或服务化只是无意义套壳时，采用单文件契约：

- 选手控制且只控制一个文件的全部字节；
- 固定 runner 在一次性 Linux 用户态进程中处理；
- 不可控制路径、argv、环境变量、网络会话或交互；
- 使用真实 CLI、官方 fuzz/test 入口，或符合公开 API 的最薄 runner；
- 同一提交在 vulnerable/fixed 走完全相同的执行与裁判。

库可以走 FILE/BIN；真实服务中可离线触发的解析器也可以走 FILE/BIN，但不得与服务题重复交付。

#### FILE-EXPLOIT

在关闭 sanitizer 的真实 release 目标上，要求未授权代码执行、受保护数据读取或其他明确越权效果。仅 crash、控制普通状态或 sanitizer 报告不合格。

本地读取必须与目标进程权限有真实边界；普通程序读取自己本就可读的文件不能称为越权。

#### FILE-POV

无法完成高阶效果，但能稳定触发指定漏洞时兜底：

- C/C++ 使用 ASan/UBSan/MSan 等，校验错误类型与相关栈；
- 其他语言使用对应 sanitizer、原生组件或明确运行时错误，不能全部强套 ASan；
- ReDoS、死循环、内存膨胀使用独立 CPU/wall-time/RSS 与同预算良性/fixed 对照；
- 普通异常、assert、任意非零退出或任意超时不算成功。

FILE-POV 是漏洞触发/fuzzing 能力的低阶交付，不冒充高阶 exploit。它对训练黑盒输入构造和漏洞复现仍有价值。

### 4.3 同实例唯一交付

```text
能做 SVC-EXPLOIT 吗？
  ├─ 能：交付 SVC-EXPLOIT
  └─ 不能或不应服务化：
       能做 FILE-EXPLOIT 吗？
         ├─ 能：交付 FILE-EXPLOIT
         └─ 不能：能做 FILE-POV 吗？
                ├─ 能：交付 FILE-POV
                └─ 不能：淘汰/暂缓
```

回退必须记录原因，不能通过任意 crash 保留高阶标签，也不能同一实例多分支重复计数。

## 5. 四阶段生产流程

### 5.1 阶段一：分支选择与准入

Agent 读取 meta、源码和已有线索，判断 **抛弃**，或在 **SVC-EXPLOIT / FILE-EXPLOIT / FILE-POV** 中选择一个分支。每个实例必须写入一个结构化路由文件 `route.json`，至少包含：

```json
{
  "instance_id": "source_CVE-ID_candidate",
  "accepted": true,
  "branch": "FILE-POV",
  "reason": "真实单文件解析入口，目标为指定内存错误的差分触发"
}
```

抛弃时写 `accepted=false` 和原因。调度器只读取 `route.json` 选择后续分支；一个输入只能进入一个分支，最终至多产出一道题。`FILE-EXPLOIT` 合成失败后可以重新评估是否回退 `FILE-POV`，但必须更新路由文件，不能同时交付两道。

### 5.2 阶段二：按分支合成

使用同一个通用执行入口，根据 `route.json` 加载对应分支 prompt。SVC、FILE-EXPLOIT、FILE-POV 可以使用不同的合成指令、产物布局、`tests/test.sh` 和 verifier，不强行统一内部实现。

Agent 完成环境、gold 和题面，保存完整执行轨迹及合成产物。此阶段做基本自检，不把它代替后续独立审查和 Harbor 终验。

### 5.3 阶段三：新 session 独立审查

开启不继承合成上下文的 review session，输入阶段二的执行轨迹、路由文件和产物。审查者判断：

- 是否伪造漏洞、篡改目标、弱化 fixed 或操纵裁判来通过；
- 是否泄漏 gold/fixed/私有裁判，或存在绕过目标漏洞的捷径；
- 分支是否合适，题面、真实入口、漏洞效果和交付产物是否一致；
- vulnerable 成功、fixed 失败、正常输入健康等声明是否有实际证据。

审查结果为通过或附具体证据的拒绝/返修意见。独立审查不是代替 Harbor 执行测试。

### 5.4 阶段四：Harbor 出包验收

按所选分支导出镜像和 Harbor profile，运行对应的 `tests/test.sh` / verifier，并从最终交付包完成 Harbor 0.22.0 验收。只有阶段三审查与阶段四验收都通过才算交付。

### 5.5 简单与通用约束

流程固定为上述四阶段，不在阶段内部再设计复杂状态机、阶段产物矩阵或自动跳转规则。一个 runner 负责执行、日志和失败记录，分支差异由路由文件和对应 prompt/verifier 承担。

### 5.6 不依赖专属 MCP 工具

合成 agent 只使用通用能力：

- shell、文件读写、编译器、容器 CLI；
- curl/netcat/官方客户端等公开工具；
- Python/Shell 等通用脚本；
- 普通文本日志和退出码。

不要求 `query_cve`、`build_challenge`、`verify_task` 等定制 MCP，不让任务提示依赖工厂私有函数或专有工具名。Harbor 是最终运行框架，不应把工厂私有 API 溶入解题轨迹。

交付题内选手也只依赖通用 shell、文件、网络和公开调试工具。`instruction.md` 说明公开入口和成功条件，不出现内部阶段名、私有路径或专用 MCP 用法。

### 5.7 轨迹保留

保存自然语言决策、通用 shell/编辑操作、程序输出和失败修正，便于转成普通 ReAct/工具调用格式。内部私有 gold、fixed 和裁判细节不得泄漏到选手轨迹或题面。

## 6. 验证与 Harbor 交付

### 6.1 最小统一裁判

所有分支共享四条底线：

1. `benign_control_ok=true`：正常输入/请求和正常权限路径可用；
2. `vulnerable_effect=true`：gold 在干净 vulnerable 环境达成指定结果；
3. `fixed_effect=false && fixed_health_ok=true`：同一 gold 在 fixed 不达成结果，且不是环境损坏；
4. 从最终交付包重复终验，结果稳定且归因于目标漏洞。

环境中可以使用固定文件、固定 secret 和固定配置，不额外引入动态 secret/nonce 机制。高阶内存利用使用无 sanitizer release；fixed、gold 和私有裁判不可被选手读取。双版本差分是重要约束，不宣称能自动排除一切旁路漏洞。

### 6.2 复用老管线的验证思想，不复制复杂度

借鉴 `exploit-from-git` 的私有 gold、vulnerable/fixed 两轮验证、持久化状态恢复与出包终验；但新实现只保留当前分支所需功能。FILE/BIN 不背服务探活、数据库卷和 Compose 状态机。

### 6.3 Harbor 目录契约

按 `docs/reference/交付格式.md` 输出，每个任务独立目录：

```text
<task-id>/
├── images/
│   └── *.tar.gz
└── harbor-runtime-profile/
    ├── task.toml
    ├── instruction.md
    ├── environment/
    │   ├── docker-compose.yaml
    │   └── assets/
    └── tests/
        └── test.sh
```

- 预构建全部目标镜像，Compose 引用与 `task.toml` 声明一致；交付不依赖在线构建。
- SVC 使用隔离攻击者/目标网络，必要的持久化数据显式初始化与恢复。
- FILE/BIN 使用一次性 runner，fixed 由私有 verifier 控制，不暴露给选手。
- `tests/test.sh` 是统一验收入口，内部调用当前分支的最小 oracle；自定义 verify 逻辑不依赖工厂工作目录。
- 共享 agent 镜像可放 bundle `shared-images/`，不在每题重复打包。
- 使用 Harbor 0.22.0 做真实启动、Agent 执行和评分终验，不能只调用工厂内部 Python 函数代替。

## 7. 开发调试与产量口径

1. 直接从候选输入中随机抽取 **100 道**，按完整四阶段流程开发和调试管线，不先限定简单题。
2. Agent 在准入和合成中自行查找所需的源码、PoC、镜像、运行入口和利用资料。
3. 统计各分支的准入、合成、独立审查和 Harbor 验收结果，以实际产物调试通用及分支 prompt。
4. 元数据线索池在路由前可以重叠；路由后每个输入只进入一个分支，至多产出一个交付实例，因此**交付候选与产量不重叠、不相加重复计数**。
5. 批量规模根据这 100 道的实际分支分布和通过率决定，不把正则召回数当作交付量。
6. **最终必须交付分布清单**：例如最终留下 10,000 条时，分别列出 `SVC-EXPLOIT`、`FILE-EXPLOIT`、`FILE-POV` 的数量；SVC 再细分 `native_service / real_host / synthetic_host`，并统计漏洞类型、语言和验收方式。只计入通过独立审查与 Harbor 验收的实例，不能用召回池数量充当交付量。

## 8. 常见问题：边界与分工

### 8.1 什么是用户态？

用户态就是漏洞位于普通应用程序中，由 Linux 内核按普通进程权限运行，而不是位于内核、驱动或虚拟机管理层；本地文件解析器和网络 daemon 都可以是用户态程序。

### 8.2 客户端和服务端是什么？

客户端是主动连接服务的浏览器、SSH 工具、数据库驱动等，服务端是监听并处理请求的 SSH 服务器、数据库等；本期排除的是“恶意服务端反过来攻击客户端”的漏洞，因为攻击角色和网络入口与 SVC 相反。

### 8.3 为什么浏览器、V8/JSC、XSS/CSRF 等不好做？

它们需要页面渲染、受害者交互或浏览器内部状态检查，普通网络/文件入口和现有裁判覆盖不了，必须另建专用环境与裁判。

### 8.4 为什么这批题目没有被老管线的一万三千条选走？

老管线只选取了其中 13,173 个普通 Web 应用实例；剩余 38,901 条主要属于非 Web、非 HTTP 或文件输入形态，不适合直接套老管线，本期按真实入口选择 SVC 或 FILE/BIN。

### 8.5 SVC 是什么？什么漏洞走 FILE/BIN？

SVC 是 service（服务）的缩写。以图片解析库溢出为例：真实输入只是一个图片文件时，给固定解析器提交图片走 FILE/BIN；存在真实或合理的宿主服务、攻击者通过网络提交图片时，才走 SVC-EXPLOIT。是否属于库不是分支边界，真实攻击入口才是。

## 9. 当前文件

- 剩余全集：`新管线开发/data/remaining-38901.instances.jsonl`
- FILE/BIN PoV 召回：`新管线开发/data/file-pov-g1.candidates.jsonl`
- FILE/BIN 高阶召回：`新管线开发/data/bin-file-exploit-g1.candidates.jsonl`
- SVC 宽召回：`新管线开发/data/svc-exploit.recall-candidates.jsonl`
- SVC 召回统计：`新管线开发/data/svc-exploit.recall-report.json`
- 新 SVC 50 条审查：`新管线开发/work/svc_exploit_recall_random50_audit.json`
- 全池随机 50 条审查：`新管线开发/work/remaining_38901_random50_audit.json`；初步为 9 条 SVC、9 条 FILE-POV、4 条待定、28 条排除，说明全池并非都属于当前两个分支，不能只用 SVC 比例外推总量。
- 旧版审查：`新管线开发/work/service_scan_random50_audit.json`
- 交付规范：`docs/reference/交付格式.md`
- 老管线参考：`reference/pass2fail_verifier.py`（仅阅读参考，不复制旧编排复杂度）
