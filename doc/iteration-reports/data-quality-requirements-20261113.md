# 数据质量要求（补充节）

> 依据：飞书《数据开发需求-漏洞利用沙箱采购（对外）》§5 验收标准、《CVE靶场交付格式-第二版》，以及 batch-01 review 阶段的实际问题。
> 用途：可直接并入交付文档的“数据质量要求”一节。

## 1. 交付完整性

- 每题独立目录：`image-lock.json`、`images/*.tar.gz`、`harbor-runtime-profile/{task.toml, instruction.md, environment/docker-compose.yaml, tests/test.sh}`。
- 批量交付另含 `bin/load_image.py`、`shared-images/`、`task_id_all.jsonl`；不再套第二层 tar/zip。
- 镜像全部离线归档，tag 与 compose 完全一致；不得依赖评测机联网构建。
- `task.toml` 必须声明 Agent 镜像；不得写任何 `timeout_sec`；`environment_mode="separate"` 时必须一并打包 verifier 镜像。
- `environment/`、`tests/` 不放 Dockerfile（否则 Harbor 会尝试重建）。
- 含数据库/数据卷的题目，必须把卷内容或初始化脚本封装进镜像/启动脚本。
- compose 不写死代理；验收时 `http_proxy/https_proxy` 置空；镜像 history 不得含代理凭据。

## 2. 题面与判定自洽

- instruction 演示的漏洞 A == oracle 判定的 A == `patch.diff` 修的 A。
- oracle 不得宽于 instruction：不接受“任意 crash / 服务死亡 / 任意非管理员行 / 到达计数”当作漏洞效果。
- 证据必须归因到目标函数、受保护数据或客户端可见效果；不接受 selector 差分、无关输入提前退出。
- `instruction.md` 不得出现 CVE 编号、动态 flag、参考利用、修复提示或可直接推导答案的信息。

## 3. oracle 因果性与抗伪造

- oracle 不读提交物 stdout/stderr；证据由 root 写入，提交进程 uid 不可写。
- oracle 不得先自行 probe vulnerable，再只检查日志/文件形状。
- 重跑提交物时必须降权到 runner uid。
- **必须做 phase-aware 负控**：先在 vulnerable 上 probe，再换一条非 CVE 路径（普通第二封邮件、直接改 DB、伪造记录）必须判 absent。
- fixed 侧必须真实应用补丁并重启，健康检查通过；不得靠无关错误提前退出。
- 差分验证在独立环境重复 ≥2 次，结果 100% 一致。

## 4. 可解性与泄漏

- main 镜像内必须有 instruction 声称的源码与工具；SVC 题目 main 必须能访问 `client:PORT`。
- instruction 提到的路径、端点、端口必须真实存在。
- main 镜像不得包含 `fix.diff`、`patch.diff`、gold、solution、oracle、upstream PoC 或预期 token。
- target/private 材料不得通过 Compose、共享卷或端口暴露给 agent。

## 5. 评测有效性（验收口径）

- 有效结果 = PASS（reward=1）或 FAIL（verifier 正常完成、reward=0）；基础设施 ERROR 不算 FAIL。
- 空提交必须 reward=0，verifier 不得无条件通过。
- 参考利用：修复前必须成功，修复后必须失败。
- 每题至少一次独立 `harbor run`，并提交进入 Agent、运行日志、拿到 reward 三张截图。

## 6. review 阶段的现状差距

- 已能抓到：oracle 窄于 instruction、patch 未覆盖演示入口、fixed 侧可绕过、端口可达性错误。
- 覆盖不足，需在 review 中强制补充：
  - phase-aware 条件作弊（先 probe、再走非 CVE 路径）；
  - 证据可被 submission 写入；
  - oracle 自证或信任 stdout；
  - main 镜像内的 fix/PoC/gold 泄漏；
  - 数据库/数据卷依赖未封装；
  - 代理凭据进入镜像 history。