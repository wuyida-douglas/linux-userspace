# 网络约定

直接使用 `docker` / `docker compose`，不需要 `sudo`、`sg docker` 或 DinD。
工作区 PATH 里的 `docker` 已处理好组权限和 Compose 网络。

## 构建镜像

管线已经给 agent 进程设置了 `DOCKER_CONFIG`，代理自动生效。直接执行：

```bash
docker build -t myimage .
docker compose build
```

**不要传 `--build-arg`，不要在 Dockerfile 里写 `ARG HTTP_PROXY`，也不要把代理
URL 写进 Dockerfile、Compose、`ENV` 或命令行。** 代理只作用于 build，不会进入镜像。

如果 build 仍然直连超时，说明当前进程没有 `DOCKER_CONFIG`：停下来报告，
不要自己加 `--build-arg`。

## 软件包源

包管理器一律用内网源：

- Ubuntu apt：`http://10.140.84.42:19090/repository/ubuntu/`
- Debian apt：`http://10.140.84.42:19090/repository/debian/`
- npm：`http://10.140.84.42:19090/repository/npm-public/`
- Go modules：`http://10.140.84.42:19090/repository/go-public,direct`
- Maven：`http://10.140.84.42:19090/repository/maven-public`
- PyPI：`https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/`

`http://10.140.84.42:19090/browse/` 是管理界面，不是软件源。

Docker Hub 镜像用普通名字：`ubuntu:22.04`、`alpine:3.19`。**不要加
`10.140.84.42:19090/` 或任何 registry 前缀**；daemon 已把 Docker Hub
透明转发到 kkRepo。其他 registry（GHCR 等）不保证可达。kkRepo 偶发 502：
稍后重试，不要绕过 mirror 直连 Docker Hub。

Dockerfile 示例（先把基础镜像的 apt 源改成上面的 kkRepo 地址）：

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends gcc make
RUN pip install --index-url https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ requests
RUN npm config set registry http://10.140.84.42:19090/repository/npm-public/
```

## 容器运行时

`DOCKER_CONFIG` 只影响 build，不会注入 `docker run` 的容器。容器里的
apt / pip / npm 仍用上面的内网源；不要往 Compose 里写代理 URL。

## 公网源码

GitHub 等公网源码在 build 的 `RUN` 里直接用官方 URL，代理已生效：
`git clone`、release、raw 文件、`codeload.github.com`、`api.github.com`。
所有请求设置 5–10 秒连接超时和明确的总超时；失败时记录实际错误，不要
无超时重试。

## 常见错误

| 写法 | 后果 |
|---|---|
| `--build-arg HTTP_PROXY="$HTTP_PROXY"` | 凭据进入 argv，`ps`/history 可见；不需要 |
| Dockerfile 写 `ARG HTTP_PROXY` 并传值 | 代理 URL 写入 `docker history` |
| `ENV HTTP_PROXY=...` | 凭据写入镜像层 |
| Compose `environment:` 写死代理 URL | 凭据进入交付文件 |
| 给 Docker Hub 镜像加 `10.140.84.42:19090/` 前缀 | 镜像名错误，拉取失败 |
| 容器运行时依赖 `DOCKER_CONFIG` 出网 | 不生效，容器内直连超时 |
| 容器内 apt / pip 用官方源 | 运行时不可达，改用内网源 |
| 访问 `10.140.84.42` / `10.12.111.133` 走代理 | 内网请求被转发，502 |