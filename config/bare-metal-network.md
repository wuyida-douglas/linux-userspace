# 网络约定

你在本工作区安装依赖、拉取镜像和访问公网时，遵循以下约定。

直接使用 Docker：运行 `docker` / `docker compose` 即可，不需要 `sudo`、`sg docker`
或 DinD。工作区 PATH 里的 `docker` 已处理好组权限和 Compose 网络分配。

## 分清两类地址

- 包管理器（apt / npm / Go / Maven / PyPI）：使用下面带 `19090` 的完整仓库 URL。
- Docker Hub 镜像：使用普通镜像名，如 `ubuntu:22.04`，**不要加 `10.140.84.42:19090/`
  或任何其他 registry 前缀**。

软件源：

- Ubuntu apt：`http://10.140.84.42:19090/repository/ubuntu/`
- Debian apt：`http://10.140.84.42:19090/repository/debian/`
- npm：`http://10.140.84.42:19090/repository/npm-public/`
- Go modules：`http://10.140.84.42:19090/repository/go-public,direct`
- Maven：`http://10.140.84.42:19090/repository/maven-public`
- PyPI：kkRepo 没有 PyPI 仓库，使用
  `https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/`，不要改成域名根路径。

`http://10.140.84.42:19090/browse/` 是管理界面，不是软件源地址。

## Docker Hub 镜像

`docker pull ubuntu:22.04`、`docker pull busybox:latest`、`FROM ubuntu:22.04`
都可直接使用：Docker daemon 已把 Docker Hub 请求透明转发到 kkRepo。因此：

- 镜像名不要加前缀，Dockerfile 里也不要引用本地代理。
- 透明转发只覆盖 Docker Hub，不覆盖 GHCR 等 registry；其他 registry 需自行确认可达。
- kkRepo 偶发 502（对上游超时 20 秒）：稍后重试或报告，不要绕过 mirror 直连 Docker Hub，
  也不要无超时地重复拉取。
- 转发只作用于 `docker pull/build/FROM`；容器内 apt / pip / npm 不会自动走它，
  仍须使用上面的仓库 URL。

## 构建或运行容器时访问公网

`docker build` 不继承 shell 的代理变量。Dockerfile 中任何会拉公网的
`RUN curl/git/wget/pip install/...` 都必须通过 `--build-arg` 传入代理，
否则 buildkit 会直连并超时。

构建时（代理变量已在本会话环境中，直接引用，不要把 URL 字面写出来）：

```bash
docker build \
  --build-arg HTTP_PROXY="$HTTP_PROXY" \
  --build-arg HTTPS_PROXY="$HTTPS_PROXY" \
  --build-arg NO_PROXY="$NO_PROXY" \
  --build-arg http_proxy="$http_proxy" \
  --build-arg https_proxy="$https_proxy" \
  --build-arg no_proxy="$no_proxy" \
  -t myimage .
```

Dockerfile：

```dockerfile
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG http_proxy
ARG https_proxy
ARG no_proxy

RUN curl -fsSL --connect-timeout 10 https://github.com/... -o /tmp/foo.tar.gz
RUN apt-get update && apt-get install -y --no-install-recommends gcc make
RUN pip install --index-url https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ requests
RUN npm config set registry http://10.140.84.42:19090/repository/npm-public/
```

`ARG` 只在构建期存在，不会写入最终镜像；`ENV` 会持久化到镜像层，`docker inspect`
可见。代理 URL 绝不能放进 `ENV`。

容器运行时需要出网时，用 Compose 变量插值，值不要写进文件：

```yaml
environment:
  HTTP_PROXY: ${HTTP_PROXY}
  HTTPS_PROXY: ${HTTPS_PROXY}
  NO_PROXY: ${NO_PROXY}
  http_proxy: ${http_proxy}
  https_proxy: ${https_proxy}
  no_proxy: ${no_proxy}
```

代理凭据不得出现在 Dockerfile、Compose、镜像、日志或命令行参数中。

## 直连与超时

- `10.140.84.42`、`10.12.111.133`、`localhost` 和 Compose 服务名必须直连，
  不要走代理（这些地址已在 `NO_PROXY` 中）。
- 公网源码通过代理从官方端点获取：`git clone`、release、raw 文件，以及
  `https://codeload.github.com/<org>/<repo>/tar.gz/<40hex>` 和
  `https://api.github.com/repos/<org>/<repo>/commits/<40hex>`。
- 所有请求设置 5–10 秒连接超时和明确的总超时；失败时记录实际错误，
  不要无超时重试，也不要猜测或输出代理凭据。

## 常见错误

| 写法 | 后果 |
|---|---|
| `RUN curl https://github.com/...`（无 ARG，无 `--build-arg`） | 直连公网，超时 |
| `ENV HTTP_PROXY=http://user:pass@...` | 凭据写入镜像层并随镜像交付 |
| Compose 的 `environment:` 里写死代理 URL | 凭据进入交付文件 |
| Dockerfile 写了 `ARG` 但构建时不传 `--build-arg` | ARG 为空，等效未设代理，静默失败 |
| 容器内 apt 用默认 ubuntu.com 源 | 不可达，改用 kkRepo URL |
| 容器内 pip 用默认 PyPI | 不可达，改用 PJLab URL |
| 访问 `10.140.84.42` / `10.12.111.133` 走代理 | 内网请求被转发，502 |