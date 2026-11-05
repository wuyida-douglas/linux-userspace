# 金属机网络约定

合成 Agent 直接使用金属机 Docker，不启动 DinD。执行环境已通过工作区 `bin/docker`
自动刷新当前用户在 /etc/group 中已有的 docker 补充组；脚本内也可直接运行
`docker ...`，无需记忆 `sg docker`。不得把 Docker socket 挂入交付的选手容器。

## 已实测的地址

**先分清两种用法：**
- apt/npm/Go/Maven 等软件源：显式使用下面带 `19090` 的完整仓库 URL。
- Docker Hub 镜像：使用普通名称，如 `ubuntu:22.04`，**不要加 `10.140.84.42:19090/` 或任何其他前缀**；
  host Docker daemon 已通过回环 mirror 自动转发到 kkRepo。

金属机统一使用自建 kkRepo：`http://10.140.84.42:19090`。已实测 Ubuntu apt
和 Docker Hub 镜像可用。`http://10.140.84.42:19090/browse/` 是管理界面，不是软件源地址。

- Ubuntu apt：`http://10.140.84.42:19090/repository/ubuntu/`
- Debian apt：`http://10.140.84.42:19090/repository/debian/`
- npm：`http://10.140.84.42:19090/repository/npm-public/`
- Go modules：`http://10.140.84.42:19090/repository/go-public,direct`
- Maven：`http://10.140.84.42:19090/repository/maven-public`
- PyPI：kkRepo 没有 PyPI 仓库。继续使用
  `https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/`，不要改成域名根路径。
- **Docker Hub 镜像直接使用普通名称，不要添加任何前缀**：
  `docker pull ubuntu:22.04`、`docker pull busybox:latest`、
  `FROM ubuntu:22.04` 均已实测成功。daemon 已配置
  `registry-mirrors=["http://127.0.0.1:18081"]`；本地 Nginx 只监听回环地址，
  将请求转发至 kkRepo 的 `docker-hub` 仓库。Dockerfile 中不要显式引用本地代理。
  只有 `docker pull/build/FROM` 走这套透明 mirror；apt 等包管理器不会走它，仍须使用上面的软件源 URL。
  kkRepo 曾出现短时 502，代理对上游设置 20 秒超时；失败时稍后重试或报告，
  不要直接改走 Docker Hub，也不要启动无超时的重复拉取。
- 该透明配置只覆盖 Docker Hub，不会自动改写 GHCR 等 registry。非 Docker Hub
  镜像需单独实测其上游或 kkRepo 对应仓库，不要假定普通 mirror 会自动代理。
- 容器内 apt 使用 kkRepo。需要公网的构建或运行命令从 shell 继承代理环境，
  不把带用户名/密码的代理 URL 写进 Dockerfile、Compose、镜像、日志或公开交付。
  镜像基础层由 host Docker 拉取，不需要把 Docker socket 挂入容器。
- 路由阶段不做网络恢复，不因缺失或不匹配的补丁/源码拒绝。合成阶段可从官方上游、
  advisory 引用和备用候选中恢复真正的修复及对应漏洞版本。同一官方端点只做有短超时的
  有界尝试，失败则记录已尝试的来源，不反复尝试代理组合。
- 本机公网使用 PT 代理 `proxy.pjlab.org.cn:23128`，不是 H 集群代理。
  pipeline 的 bash 工具自动从用户私有凭据文件加载代理；交互 shell 也加载该配置。
  `localhost`、私网、kkRepo、模型网关和容器服务名必须直连。
- 若代理未生效，由管理员运行 `config/setup-pt-proxy.sh`，输入 AD 用户名和
  Authentik 应用密码。agent 不得猜测、打印或向交付传递代理凭据或模型密钥。
- C/C++ sanitizer 构建至少显式安装 `gcc libc6-dev linux-libc-dev make`（或
  `build-essential`）；单独 `gcc --no-install-recommends` 已实测缺少 Scrt1.o/crti.o。
  如果运行其他目录中的 ASan 二进制，还要安装 `libasan6`（Ubuntu 22.04 GCC 11），
  否则会出现 `libasan.so.6: cannot open shared object file`。ASan 诊断必须配合
  `detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0` 和目标级 `timeout`，日志写入有界文件；
  本机 Docker ASan 符号化已最小复现无限 DEADLYSIGNAL，禁止省略 `symbolize=0`。
  不要把无限 `AddressSanitizer:DEADLYSIGNAL` 输出当成漏洞差分或让它持续写磁盘。

## 公网与源码恢复

未认证 PT 代理会返回 407；配置认证前，`github.com`、`raw.githubusercontent.com`、
`www.google.com`、`www.baidu.com` 实测直连超时。代理配置成功后可用正常官方
`git clone`、release、raw 文件和归档；`codeload.github.com` 与 `api.github.com`
也可作为 GitHub 源码恢复端点。网络请求使用 5–10 秒连接超时和明确的总超时，
不要无超时地运行 `curl`；失败则记录实际错误，不反复重试。

`input/src/` 和 `input/fix.diff` 是 S3 提供的**候选证据，不保证完整、匹配或正确**。
可能缺少源码/补丁、已经修复，或者候选 commit 只改文档、版本或 fuzz harness。
路由阶段不得仅因此拒绝；合成阶段应主动调查官方上游、advisory 引用和备用候选，
找回真实安全修复及其漏洞父版本。允许从官方仓库 clone 或获取归档来恢复、核验和
替换错误证据，但不能修改 `input/` 原始材料，也不能把无关最新源码当作恢复结果。
GitHub 仓库可优先尝试：
`https://codeload.github.com/<org>/<repo>/tar.gz/<40hex>`，以及
`https://api.github.com/repos/<org>/<repo>/commits/<40hex>` 查询 commit 和父版本。
恢复来源、revision、下载内容 SHA 和验证依据必须写入
`delivery/project/source-recovery.json`。不得用无关补丁或纯版本差异冒充漏洞修复。
容器内部服务名、`localhost`、内部 kkRepo 均必须直连。

公开 Compose 不得包含 gold、fixed、私有 verifier、模型凭据或宿主机敏感路径。
私有测试材料只提供给评测控制面和独立 verifier；不得挂载或复制到选手 main、target 或公开分发子集。
