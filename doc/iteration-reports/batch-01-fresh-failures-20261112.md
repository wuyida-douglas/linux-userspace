# batch-01 fresh 运行错题分析（2026-11-12）

> 批次：`samples/batch-01/fresh-todo.txt`，1562 道从未尝试过的题
> 运行窗口：2026-11-12 12:14 – 14:25 UTC，DeepSeek、80 并发
> 目的：解释为什么成功率偏低，重点回答“是不是网络问题”。

## 0. 结论

**不是网络问题。**

- 所有 `error` 的报错里没有 DNS、apt、pip、proxy、连接失败之类的字样；
- 镜像重建失败的 15 道全部是 `not found`（构建上下文缺文件），不是拉不到依赖；
- 构建阶段已经通过 `DOCKER_CONFIG` 注入了代理（`pipeline/agent.py::docker_config_environment`），本轮没有一条构建因为网络失败。

失败集中在三个可解释的类别：**交付包缺构建上下文导致镜像无法重建（28 道）**、**review 判定的题目自洽/质量问题（18 道）**、**合成阶段模型侧失败（7 道）**。

## 1. 当前计数（分析时点）

| 状态 | 数量 |
|---|---:|
| passed | 26 |
| review_rejected | 18 |
| error（镜像相关） | 28 |
| error（其他） | 5 |
| synthesis_blocked | 6 |
| synthesis_incomplete | 1 |

可计分成功率在 27%–37% 之间波动（分母会随重排变化）。

## 2. 失败分类与证据

### 2.1 镜像缺失 / 重建失败（28 道，最大一类）

两类报错：

```text
RuntimeError: image <ref> is missing and none of ('main/Dockerfile', 'Dockerfile.main') exists in .../delivery/project
```

```text
RuntimeError: failed to rebuild <ref>: ... failed to calculate checksum of ref ...:
"/transformers-vuln-src.tar.gz": not found
"/main-src": not found
```

原因：

1. 合成阶段构建镜像时，构建上下文不止 `delivery/project/`，还包括 workspace 里临时下载的源码包（`*.tar.gz`、`main-src/`、`vendor/` 的某些文件）；
2. 交付包只打包了 `project/{main,client,vendor}` 等文件，**大文件/临时目录被排除**；
3. 我们为了回收磁盘，在任务终态时删除了任务镜像；
4. 这些题被重排后，`harbor.export()` 的“镜像缺失则从 delivery 重建”逻辑找不到构建上下文，于是失败。

**这不是网络问题，是交付包不自包含。** 只要镜像还在本地，这些题本来可以正常验收。

短期处理：这类题标记为“不可重建”，不再重排（重排必然失败）。
长期处理（建议）：交付包必须包含构建上下文，或在合成阶段把构建用的 tar/源码目录复制进 `delivery/project/` 并纳入打包；否则任何镜像清理都会让这些题不可恢复。

### 2.2 review_rejected（18 道，模型侧质量问题）

review agent 判定交付不成立，典型证据：

- **oracle 比 instruction 窄**：例如 `linux-489`，oracle 只扫 `/srv/runs`，instruction 要求的是任意位置生成文档；
- **patch 没修 instruction 演示的漏洞**：例如 `linux-504`，oracle 判定的输入类不是 `patch.diff` 修的那一类；
- **fixed 侧可绕过**：例如 `linux-493`，在打了补丁的 fresh target 上跑 `solution.sh` 仍然能触发效果（有直接证据）；
- **端口/网络假设不成立**：例如 `linux-505`，instruction 声称不可达的 `client:9000` 实际可达。

这些是合成质量与自洽性问题，不是环境/网络。对应的 prompt 收紧方向：oracle 必须与 instruction 的判定面一致；patch 必须覆盖 instruction 演示的入口；fixed 侧必须验证 solution 不再触发。

### 2.3 其他 error（5 道）

- `routing agent did not complete: agent_error`（2 道）：路由 agent 会话异常结束，模型/会话侧问题，与网络无关；
- `shared image archive differs from already published copy: .../shared-images/agent.tar.gz`（3 道）：发布时新生成的共享镜像归档与 `harbor_export/20261111-production/shared-images/agent.tar.gz` 不一致。本地镜像 ID 与 manifest 一致（`sha256:82e17847…`），更像是并发发布/重复打包导致的归档字节差异，需要单独核对（不影响题目本身，只是导出校验拒绝）。

### 2.4 synthesis_blocked / incomplete（7 道）

`synthesis_blocked` 的日志末尾显示后台任务被 kill（子任务状态 `killed`），随后 agent 报告“unworkable route”。这更像是**轮次/时间耗尽或 agent 主动放弃**，不是网络；需要逐题看 `synthesis/live.chat.md` 才能区分“确实没有可行路径”与“被截断”。

## 3. 为什么成功率看起来低

- 本次批次第一次运行时，开局 1 小时内大量题还在合成，终态主要是 **失败**（review/error），通过的题要等“合成 → 评审 → 验收 → 发布 → final differential”整条链路完成才落账；
- 镜像清理把一批“本可验收”的题变成了 error（2.1），直接拉低了成功率；
- 分母里同时包含模型侧失败（review_rejected / blocked），这是当前 DeepSeek + 这套 prompt 的真实产出。

## 4. 建议的下一步

1. **交付包自包含**：把构建需要的 tar/源码目录纳入 `delivery/project/` 并打进 bundle（或在合成结束后统一复制），否则镜像清理不可逆；
2. **不可重建的题不再重排**：在 `requeue` 逻辑里识别 `is missing`/`failed to rebuild`，直接终态；
3. review 收紧：oracle 判定面 == instruction 演示面；fixed 侧必须验证 solution 不再触发；
4. 核对 `shared-images/agent.tar.gz` 的归档差异（3 道），确认是字节级差异还是镜像内容变化；
5. 继续观察 rate：如果 2.1 类失败被止住，成功率应回到 35%–45% 区间（历史 batch-01 同管线水平）。