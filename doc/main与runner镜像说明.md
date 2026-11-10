# main、client、runner：镜像、容器与验收边界

> 适用版本：`/nvme/wuyida/新管线开发` 当前工作区，2026-11-10。
> 本文专门解决“main 镜像到底用哪个、runner 是不是要新镜像、agent 在不在
> main 里跑”这几个容易混淆的问题。

---

## 0. 一句话

```text
main    = 选手的“分析工作站”容器，用来读源码、写 exploit
client  = 漏洞目标容器（名字叫 client，其实就是 target）
runner  = 评分时临时创建的“不可信提交执行”容器，选手看不到
```

三个分支（SVC / FILE-EXPLOIT / FILE-POV）都是这个结构；区别只在
submission 形态和 oracle/solution 的细节。

合成 Agent 本身**不在 main 里**。它是宿主机上的 `claude -p` 进程，用宿主
Docker/Compose 去构建、启动、`exec` 这些容器。

---

## 1. 角色与可见性

| 名称 | 镜像来源 | 谁创建 | 选手可见 | 评分时可见 | 用途 |
|---|---|---|---|---|---|
| **合成 Agent** | 宿主机 `claude` | 控制器 | 否 | 否 | 读输入、写 `delivery/`、跑测试 |
| **main** | 公开 Compose `main.image`（控制器生成 `task.json.images.agent`） | Harbor / 选手 | **是** | 只在做题阶段 | 分析工作站：bash、python3、源码、工具 |
| **client** | 公开 Compose `client.image`（控制器生成 `task.json.images.target`） | 合成 Agent / Harbor | **是** | 是（私有副本） | 真实漏洞目标 |
| **runner** | 固定复用 `images.agent`（即 main 镜像） | verifier | **否** | 是（私有） | 以 uid 65534 跑不可信提交 |
| **verifier** | 宿主机 Python | Harbor / 控制器 | 否 | 是 | 起 client+runner、执行 oracle/solution |

公开 Compose 只有 `main` + `client`；`runner` 永远不在公开环境里。

---

## 2. main 镜像到底用哪个

### 2.1 两种合法选择

**选择 A：共享分析镜像（推荐）**

```text
linux-userspace-agent:22.04
```

由 `pipeline.runtime_images` 准备，包含：

- `/bin/bash`
- `python3`
- `/usr/bin/env`
- 常用分析工具（file、binutils、gdb、curl、iproute2 等）

公开 Compose 的 `main.image` 写这个 tag；控制器生成
`task.json.images.agent`。它会被放进导出的 `shared-images/agent.tar.gz`，多个题共享。

**选择 B：task-specific main 镜像**

只有共享镜像缺工具时才需要：

```text
delivery/project/main-image/Dockerfile
```

可以 `FROM ubuntu:22.04`，但必须自己装上 `/bin/bash`、`python3`、
`/usr/bin/env` 和题目需要的分析工具，然后：

```bash
docker build -f project/main-image/Dockerfile -t mytask-main:1 .
```

- 公开 Compose 的 `main.image` 写 `mytask-main:1`；
- 控制器据此生成 `task.json.images.agent`；
- 导出时会把它放进该题的 `images/agent.tar.gz`，不影响其他题。

### 2.2 为什么不能直接写 `ubuntu:22.04`

裸 `ubuntu:22.04` 不是合格的 main：

- 没有 `python3`（Harbor 会用 `python3 -c ...` 启动 main）；
- 没有安装题目需要的分析工具；
- 它只是一个基础层，不是本题的 prebuilt image。

`ubuntu:22.04` 可以作为 Dockerfile 的 `FROM`，但最终必须 build/tag 成
公开 Compose 的 `main.image`；控制器再生成 `task.json.images.agent`。

### 2.3 “MISSING”是什么意思

`docker image inspect linux-userspace-agent:22.04` 报 MISSING，表示**当前这台
机器的本地 Docker 没有这个 tag**，不代表合同不允许用它。处理：

```bash
cd /nvme/wuyida/新管线开发
.venv/bin/python -m pipeline.runtime_images
```

或者走选择 B，自己 build 一个 task-specific main。

Docker build/pull 的基础层会走配置的 mirror；不是每题都重新 pull
`ubuntu:22.04`。共享镜像只准备一次。

### 2.4 合同要求（最容易错的地方）

**不要再手写 `delivery/task.json`。** 控制器在冻结前从 route、Compose 和
固定脚本生成它。main/client 镜像以公开 Compose 为准：

```yaml
services:
  main:
    image: mytask-main:1
  client:
    image: mytask-client:1
```

生成结果：

```json
"images": {
  "agent": "mytask-main:1",
  "target": "mytask-client:1"
}
```

`main.image` 不能是 target 镜像，也不能与 `client.image` 相同。main 可以
使用共享 `linux-userspace-agent:22.04`，也可以是 task-specific 分析镜像；
写哪个，控制器就生成哪个 `images.agent`。

导出时 `copy_environment()` 会删除公开 profile 的 `main.image`，把
`task.toml [environment].docker_image` 设为生成的 `images.agent`；Harbor
用这个镜像启动 main。target 镜像仍来自 Compose `client.image`，并被打成
`target.tar.gz`。

## 3. runner 是什么，为什么必须单独一个容器

### 3.1 runner 的隔离边界

评分阶段，verifier 创建**私有 Compose**：

```text
client  ← 目标，注入 /private（oracle/solution/patch/gold）
runner  ← 不可信提交执行器
```

runner：

- 镜像固定是 `images.agent`（main 的分析镜像）；
- **必须和 target 镜像不同**，但可以复用 main 的分析镜像；
- 启动时是 root，但只有 `SETUID`/`SETGID`，随后永久降权到
  `runner.user`（通常 `65534:65534`）；
- rootfs 只读，`/tmp` 是 tmpfs；
- 只挂载提交、`/work`、`/output`、`runner.py`、公开 healthcheck；
- **没有** target 文件系统、`/private`、oracle/patch/gold、Docker socket。

### 3.2 为什么不能和 target 共用容器/镜像

如果 runner 和 target 共用容器或镜像：

- 提交可以直接读 `/private/oracle.sh`、`patch.diff`、gold，甚至直接改 target；
- 提交可以读 target 文件系统里的 flag/secret；
- 提交可以杀掉/替换 target 进程，oracle 结果不可信；
- 提交可能拿到 target 的网络身份或挂载。

所以必须：

1. **不同容器**：runner 和 client 分开；
2. **不同镜像**：runner 镜像不能等于 target 镜像；
3. **不同挂载**：runner 只拿提交和公开配置；
4. **低权限**：uid/gid 65534，`no-new-privileges`，cap_drop ALL；
5. **公开环境不出现 runner**：它只在 verifier 的私有 Compose 里。

### 3.3 “全新镜像”还是“全新容器”？

容易混淆的点：

- **必须新建的是 runner 容器**，每个 phase 一个；
- **不新建第三个镜像**；runner 固定复用 `images.agent`（main 的分析镜像）；
- 同一镜像只是起点：runner 容器会做 root→65534 降权、cap_drop ALL、
  rootfs 只读、只挂提交和 `/work`、`/output`，与 main 容器的运行配置完全不同。

所以“runner 用一个全新的镜像”是不准确的。准确说法是：

> runner 是一个**独立的、一次性的容器**，固定使用 main 的分析镜像；它和
> target 必须是不同镜像，但不需要专门再造一个镜像。

### 3.4 FILE-POV 的例外

FILE-POV 的提交是 `input.bin`（数据，不是代码）。verifier 会：

1. 把 `input.bin` `docker cp` 到 client 的 `/run/pass2fail/input.bin`；
2. 在 client 里以 `runner.user` 执行 `public_runner`；
3. oracle 在 client 里检查效果。

runner 服务仍然存在（用于公开 healthcheck/public_runner 的私有执行环境），
但**提交不经过 runner 容器**。这也是为什么 FILE-POV 的 `runner.command`
必须是空数组，执行器写在 `public_runner` 里。

### 3.5 linux-026 是不是“runner 的错”？

不是 runner 本身的问题，是 **healthcheck 选错了工具、又在错误的容器里自测**：

```text
private/healthcheck.sh: exec node /opt/healthcheck/probe.mjs
合成时的自测: docker exec -u 65534:65534 l32887r08-client-1 /opt/healthcheck/check.sh
  (2026-11-10 之后 runtime 路径统一为 /healthcheck.sh)
  -> 在 client 里跑；client 是 node:22-slim，有 node 和 probe.mjs，exit 0
评分时的执行: runner 镜像 = images.agent = l026cve32887main:1
  -> 该镜像只保证 bash/python3/env，没有 node，也没有 probe.mjs
  -> exit 127
```

runner 的隔离和身份是对的；错在 healthcheck 依赖了 runner 镜像不保证的
`node`，并且 agent 只在 client 里验证过它。修法：

- 把 healthcheck 改成 python3 的 HTTP 请求；
- 或把 node 和 probe 装进 `images.agent`，重新 build/tag。

审查时必须在 runner 镜像里、以 uid 65534 执行**最终的** healthcheck；
`exit 127` 是 blocker，不是 target 不健康。

---

## 4. 导出/验收时的镜像变化

```text
delivery:
  compose main.image   = mytask-main:1
  compose client.image = mytask-client:1
  task.json            = 控制器生成，images.agent/target 来自上面两行

导出 profile:
  main: 没有 image
  client: mytask-client:1
  task.toml [environment].docker_image = mytask-main:1
  task.toml artifacts = /workspace/<submission>

Harbor:
  用 mytask-main:1 启动 main
  用 mytask-client:1 启动 client
  收集 /workspace/<submission>
  然后销毁选手环境，调用 verifier

verifier:
  新建私有 Compose：client + runner
  runner 固定用 images.agent
```

main 的 `command` / `entrypoint` / `working_dir` / `healthcheck` 在导出时会被
固定：

```yaml
main:
  working_dir: /workspace
  entrypoint: ["/usr/bin/env"]
  command: ["python3", "-c", "... time.sleep(10**9)"]
  healthcheck: ["CMD", "sh", "-c", "kill -0 1"]
```

所以不要依赖 main 镜像自带 healthcheck 在评分时生效；它会被替换。

---

## 5. linux-066 案例（历史）：agent 为什么写错

这是旧合同时代的轨迹，agent 同时写了 Compose 和 `task.json`：

1. turn 63 写 `environment/docker-compose.yaml`：

   ```yaml
   main:
     image: linux-userspace-agent:22.04
   ```

2. turn 64 写 `task.json`：

   ```json
   "images": { "agent": "linux-066-cve-2026-26983-main:filepov", ... }
   ```

3. turn 95 才 build task-specific main：

   ```bash
   docker build -f Dockerfile.main -t linux-066-cve-2026-26983-main:filepov .
   ```

但它**没有回头把 Compose 的 `main.image` 改成 task-specific tag**，于是：

```text
task.json.images.agent = linux-066-...-main:filepov
compose main.image     = linux-userspace-agent:22.04
```

这不是“main 用了 target”，而是两个文件不一致。

新合同已经取消“agent 手写 task.json”：agent 只写 Compose main.image，
控制器生成 `task.json.images.agent`。所以这类冲突不会再出现；旧交付如果仍有
不一致的 task.json，控制器会以 Compose main.image 为准重新生成。

---

## 6. `solution.sh` 是唯一修复入口

```text
verifier phase("fixed")
  → docker compose exec client /private/solution.sh
      → 应用官方 patch
      → 如果是编译型：在 solution.sh 内直接离线编译
      → 替换实际运行的 binary/library
      → 重启服务（在 solution.sh 内完成）
      → 验证 patched health
  → 用同一份提交再跑
  → oracle 必须 exit 1
```

- **`solution.sh`**：fixed 阶段唯一入口，由 verifier 调用；patch、离线 build、
  替换、重启和健康检查全部在它里面完成。
- 解释型语言可以 patch + 重新编译字节码/重装；编译型漏洞必须在
  `solution.sh` 内替换实际 binary。


---

## 7. 速查

| 问题 | 答案 |
|---|---|
| Agent 在 main 里跑吗？ | 不在；Agent 在宿主机，main 是交付给选手的分析容器 |
| 合成时 agent 会用 main 调试吗？ | 会；常用 main 镜像/容器跑 healthcheck、gold 和协议探针 |
| main 镜像必须自己 build 吗？ | 不必；Compose main.image 可写共享 `linux-userspace-agent:22.04`，缺工具才 build task-specific |
| 裸 ubuntu:22.04 能当 main 吗？ | 不能直接当；可以作为 Dockerfile 的 FROM，最终 tag 必须写进 Compose main.image |
| runner 必须新镜像吗？ | 不必，也不支持独立镜像；必须新**容器**，镜像固定复用 `images.agent` |
| runner 为什么不能和 target 共用？ | 提交会读到 target 文件系统/私有 oracle/patch/gold，结果不可信 |
| build/commit 了但 Compose 没引用？ | 不导出、不能评分；Scoring 用到的镜像必须在 Compose 里声明 |
| 改了容器但 Dockerfile 没更新？ | 不允许；交付必须能从 `delivery/project/` 的构建上下文复现 |
| FILE-POV 的 public_runner 写在哪？ | 公开 Compose 的 `client.x-public-runner.argv`，控制器生成 `task.json.public_runner` |
| main.image 写什么？ | 写最终分析镜像 tag；控制器据此生成 `task.json.images.agent` |
| 导出时 main.image 会怎样？ | 被删除；Harbor 用 `task.toml [environment].docker_image = 生成的 images.agent` 注入 |
| main 的 healthcheck 评分时用哪个？ | 被固定为 `kill -0 1`；不要依赖镜像自带 healthcheck |
