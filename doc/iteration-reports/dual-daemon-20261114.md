# 双 daemon 分片（2026-11-14）

目标：把一批题分给两个 docker daemon（各 40 并发），发布到两个目录
（`harbor_export/..._1`、`..._2`），避免单 daemon 在 80 并发下的锁竞争。

## 1. 第二个 daemon（已在本机装好）

| 项 | daemon A（原） | daemon B（新增） |
|---|---|---|
| socket | `/var/run/docker.sock` | `/run/docker2.sock` |
| data-root | `/nvme/docker` | `/nvme/docker2` |
| containerd socket | `/run/containerd/containerd.sock` | `/run/containerd2/containerd.sock` |
| containerd root | 默认 | `/nvme/containerd2` |
| docker0（bip） | 172.17.0.1/16 | **172.19.0.1/16** |
| 默认地址池 | 172.17–172.31 | **100.64.0.0/10, size 24** |
| IPAM factory 池 | 10.80.0.0/12 | **10.96.0.0/12** |
| IPAM harbor 池 | 10.112.0.0/12 | **10.128.0.0/12** |

两个池与默认池都**互不相交**，主机上不会出现重复网段。

systemd 单元（已启用）：

```ini
# /etc/systemd/system/containerd-d2.service
[Service]
ExecStart=/usr/bin/containerd --address /run/containerd2/containerd.sock \
    --root /nvme/containerd2 --state /run/containerd2

# /etc/systemd/system/docker-d2.service
[Service]
ExecStart=/usr/bin/dockerd --config-file /etc/docker/daemon-d2.json
```

`/etc/docker/daemon-d2.json` 里是 data-root、containerd socket、bip、
default-address-pools、registry mirror、日志参数。启动/检查：

```bash
systemctl status docker-d2
DOCKER_HOST=unix:///run/docker2.sock docker info
```

## 2. 代码改动

- `pipeline/docker_ipam.py`
  - `POOLS` 支持 `PIPELINE_IPAM_FACTORY_POOL` / `PIPELINE_IPAM_HARBOR_POOL` 覆盖；
  - 租约目录按 `DOCKER_HOST` 哈希区分（两个 daemon 不共享 leases.json）；
- `config/bin/docker` 本来就透传环境，`DOCKER_HOST` 生效（已实测）；
- verifier / harbor / cleanup 的 docker 调用都走 `config/bin/docker` 或
  `PASS2FAIL_DOCKER`，因此进程级 `DOCKER_HOST` 即可把整条链路切到 daemon B；
- 每个 coordinator 各自跑 housekeeping（网络、卷、镜像、TMPDIR、构建缓存），
  即两个 daemon 各自被清理，无需额外代码。

## 3. 启动一批（分片）

```bash
scripts/start_dual.sh samples/batch-02 results/batch-02 harbor_export/20261114-production \
    samples/batch-02/fresh-todo.txt 40
```

脚本做三件事：

1. 把任务清单**轮转切成 `dual-a.txt` / `dual-b.txt`**（两半题量与题型分布接近）；
2. 启动 coordinator A：默认 socket、`results/batch-02-a`、发布到 `<root>_1`、并发 40；
3. 启动 coordinator B：`DOCKER_HOST=unix:///run/docker2.sock`、专用 IPAM 池、
   `results/batch-02-b`、发布到 `<root>_2`、并发 40。

## 4. 收尾与合并

- 两个 `results` 目录独立，监控分别看（`scripts/monitor_tick.py --results results/batch-02-a`）；
- 两批都结束后，把 `<root>_2` 的题目录并入 `<root>_1`（同名不冲突，任务互斥），
  再用 `scripts/refresh_exported_verifier.py` 统一刷新 verifier；
- 发布合并前确认两边 `shared-images/agent.tar.gz` 字节一致（同一镜像归档，
  若不一致以较新的一份为准并刷新 image-lock 的 sha256）。

## 5. 已验证

- `docker-d2` 正常启动（Docker 29.1.3、overlayfs、root=/nvme/docker2）；
- 用真实 compose + `config/bin/docker` 在 daemon B 上起网络，分配到的子网是
  **10.96.1.0/24**（来自 B 的 factory 池），daemon A 上没有该网络；
- `synthesize_batch --dry-run` 在 `DOCKER_HOST=daemon B` + 专用池下正常工作；
- 178 个单测全部通过。

## 6. 注意

- **不要**给两个 daemon 分配重叠的默认地址池或 IPAM 池（会抢同一网段）；
- daemon B 的磁盘是 `/nvme/docker2` + `/nvme/containerd2`，清理同样走 housekeeping；
- 同一个 `results` 目录只能有一个 coordinator（supervisor 锁），所以分片必须用
  不同的 `results` 目录。