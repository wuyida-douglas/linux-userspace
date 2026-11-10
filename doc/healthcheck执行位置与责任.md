# healthcheck：谁在什么时候、在哪个容器里执行

> 适用版本：`/nvme/wuyida/新管线开发`，2026-11-10。
> 本文只讲 healthcheck 的执行位置和责任划分，不重复交付合同的其它字段。

先消除一个歧义：这个项目里“healthcheck”指三样不同的东西。

| 名称 | 是什么 | 用途 |
|---|---|---|
| `delivery/private/healthcheck.sh` | 题目作者写的**正常功能探针脚本** | 评分前后的功能检查 |
| `task.json.healthcheck.argv` | 执行契约，固定 `["/healthcheck.sh"]` | 告诉 verifier 在容器里执行哪个路径 |
| 公开 Compose 的 `healthcheck:` | 容器存活探针（Compose/Harbor 用） | 只表示容器起来了，不判断漏洞效果 |

下面说的都是前两种；Compose 的 `healthcheck:` 只影响 `--wait` 和 Harbor 的容器状态。

## 1. 时间线

```text
Harbor 做题阶段
  main/client 由公开 Compose 启动；Compose healthcheck 只检查容器存活

Harbor 结束后，宿主 verifier 启动私有 Compose（client + runner）
  1. compose up --wait           # 两个容器 healthy（存活探针）
  2. 上传 private/ 到 client:/private（root-only）
  3. health 阶段                  # 本文重点
  4. submission 阶段
  5. oracle 阶段
  6. fixed 阶段：solution.sh -> 重启 -> patched_health -> 同一 submission -> oracle
```

`health` 和 `patched_health` 的区别只是执行时机：前者在提交前，后者在
`solution.sh` 应用官方修复后。它们执行的是**同一个** `task.json.healthcheck.argv`。

## 2. 各分支在哪里执行

### SVC-EXPLOIT / FILE-EXPLOIT

```text
verifier: docker compose exec -T runner /opt/pass2fail/runner.py --health
runner.py: 以 root 启动 -> 降权到 runner.user（65534:65534）-> 执行
           task.json.healthcheck.argv = ["/healthcheck.sh"]
```

- 脚本来自 `delivery/private/healthcheck.sh`，verifier 复制成
  `runner/public_healthcheck.sh`，再挂到 runner 的 `/healthcheck.sh`（只读）。
- 在 **runner 容器**里执行，身份是 **uid/gid 65534**。
- 脚本运行在 runner 的网络命名空间里，通过 Compose DNS 访问目标
  （例如 `client:3000`），不访问 target 文件系统。
- 因此脚本和它引用的 companion 文件（另一个 `.py`/`.mjs`/配置模板、解释器等）
  **必须存在于 runner 镜像**，也就是 `images.agent`（main 镜像）。只存在于
  client 镜像里的 `node`、`probe.mjs` 之类在评分时不可用。

### FILE-POV

```text
verifier: docker compose exec -T client /healthcheck.sh
```

- 脚本同样是 `delivery/private/healthcheck.sh`，verifier 复制成
  `runner/public_healthcheck.sh`，挂到 **client** 的 `/healthcheck.sh`（只读）。
- 在 **client 容器**里执行，身份是容器默认的 **root**（这里不是执行选手提交）。
- 提交物是数据 `input.bin`，由 verifier 复制到 client 的
  `/run/pass2fail/input.bin`，再以 uid 65534 执行 `public_runner`。
- 所以 FILE-POV 的 healthcheck 可以使用 client 镜像里的工具；但
  `public_runner` 和输入必须能被 uid 65534 读取/执行。

### 汇总

| 分支 | healthcheck 执行容器 | 身份 | target 怎么访问 | 脚本依赖必须存在于 |
|---|---|---|---|---|
| SVC-EXPLOIT | runner | 65534:65534 | Compose 网络 `client:PORT` | `images.agent`（main 镜像） |
| FILE-EXPLOIT | runner | 65534:65534 | Compose 网络 `client:PORT` | `images.agent`（main 镜像） |
| FILE-POV | client | root | 本机/容器内 CLI | client 镜像 |

runner 镜像不是单独构建的：它固定复用 `images.agent`。见
[main 与 runner 镜像说明](main与runner镜像说明.md)。

## 3. 作者自测规则

### SVC-EXPLOIT / FILE-EXPLOIT

不要只在 main 或 client 里用 `docker exec` 试一下就算通过。最终自测必须是：

```text
镜像 = images.agent（main 镜像）
身份 = uid/gid 65534
文件系统 = 只读 rootfs；只有 /work、/output、/tmp 可写
脚本路径 = /healthcheck.sh
```

最小复现方式：

```bash
docker run --rm \
  -u 65534:65534 \
  --network <compose-network> \
  --read-only \
  -v "$PWD/delivery/private/healthcheck.sh:/healthcheck.sh:ro" \
  -v "$TASK_TMP/hc-work:/work" \
  <images.agent> \
  /healthcheck.sh
```

如果 healthcheck 还引用 `/opt/...` 下的 companion 文件，把它们一起挂载或用
`images.agent` 的构建上下文装进镜像；只存在于 client 的文件在评分时不存在。

### FILE-POV

healthcheck 在 client 里跑，可以用 client 镜像的全部工具；但要单独验证
`public_runner` 在 uid 65534 下可执行、输入文件可读。healthcheck 本身不作为
提交内容，不需要满足 65534 的读权限。

## 4. 返回码语义

- `healthcheck` 只表达“正常功能是否成立”：exit 0 = 健康，非 0 = 不健康。
- 它不是 oracle：不能在 healthcheck 里判断漏洞效果是否存在。
- SVC/FILE-EXPLOIT 的 `health` 阶段非 0，verifier 直接停在该阶段
  （`error_stage=health`），不会继续跑提交；`exit 127` 表示脚本/解释器缺失，
  属于交付缺陷，不是“target 不健康”。

## 5. linux-026 复盘：到底是谁的锅

linux-026（CVE-2026-32887，SVC-EXPLOIT / real_host）失败在 `health` 阶段：

```text
private/healthcheck.sh: exec node /opt/healthcheck/probe.mjs

合成时 agent 的自测:
  docker exec -u 65534:65534 <client-container> /opt/healthcheck/check.sh
  -> 在 client 里跑；client 是 node:22-slim，有 node 和 probe.mjs，exit 0

评分时 verifier 的执行:
  compose exec runner /opt/pass2fail/runner.py --health
  -> 降权到 65534 后执行 /opt/healthcheck/check.sh（当时路径）
  -> runner 镜像 = images.agent = l026cve32887main:1
  -> 该镜像只有 bash/python3/env，没有 node，也没有 probe.mjs
  -> exit 127
```

责任划分：

1. **主要是合成 Agent 的交付缺陷**：healthcheck 依赖了 client-only 的运行时，
   且只在 client 里验证过，没有按合同在 runner 镜像里以 65534 自测。
2. **审查阶段漏检**：REVIEW 要求“在 runner 镜像里以 uid 65534 执行最终
   healthcheck”，当时没有执行到这一条。
3. **不是 runner 的错**：runner 的镜像选择、隔离和降权都符合合同；它只是
   忠实地报告了“这个脚本在 runner 镜像里跑不起来”。
4. **不是 FILE-POV**：这是 SVC / real_host；FILE-POV 的 healthcheck 本来就在
   client 里跑，但该题不是 FILE-POV。

## 6. linux-026 当时的 prompt 到底说了什么

对照 `results/iterate-20261109-08/batch-001/cve-2026-32887-.../synthesis/prompt.md`：

**已经说了的：**

```text
The healthcheck makes a normal public-protocol request from the isolated runner,
which receives only the read-only submission and public configuration, never
private files or Docker.
```

也就是说，“SVC 的 healthcheck 在 runner 里跑”这一点当时是写了的。单看这条，
agent 把 healthcheck 只在 client 里自测，属于没有按 prompt 执行。

**没说清楚的：**

1. 没有说 healthcheck 的**解释器和 companion 文件**必须存在于 runner 镜像。
   当时只对 `exploit.py` 说了 “A tool that exists only in a modified main
   container will be missing in the runner”；healthcheck 沿用了 client-only 的
   `node` 和 `probe.mjs`，prompt 没有直接拦住。
2. 有一句误导：`healthchecks run as root but submissions run as the declared
   uid`。实际上 SVC/FILE-EXPLOIT 的 healthcheck 也是降权后以 65534 执行的；
   这句话容易让人以为 healthcheck 跑在 target/client 上。

**当前 prompt 已改为逐分支写明：**

- SVC / FILE-EXPLOIT：

  ```text
  The healthcheck argv is executed inside the runner container
  (always built from images.agent) as uid 65534, not inside client or main.
  Every interpreter, tool and companion file it references must exist in that
  image or be mounted there; target-only runtimes (for example node) and files
  baked only into client are not available.
  ```

- FILE-POV：

  ```text
  the healthcheck runs on client as root, so it may use interpreters and
  companion files from the client image. The public_runner submission still
  runs as the declared unprivileged uid ...
  ```

所以责任划分是：**位置当时说了，agent 没照做；但依赖要求和 uid 描述当时不清楚，
prompt 也有责任。现在的 prompt 已经把这两点补明确。**

## 7. 代码位置

```text
pipeline/contract_build.py       _healthcheck(): 统一生成 /healthcheck.sh
pipeline/task_contract.py        默认值、旧路径兼容、冻结前规范化
pipeline/pass2fail_verifier.py   phase(): health / patched_health 的执行位置
pipeline/pass2fail_verifier.py   runner.py 脚本: 降权后执行 healthcheck argv
pipeline/prompts.py              作者自测要求（runner 镜像 + uid 65534）
```