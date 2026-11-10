# 可写 Bind 恢复说明

> 版本：2026-11-10。解释 `pristine-binds.tar`、`extract_pristine_binds()`、
> Harbor wrapper 和 verifier 内部恢复点分别在防什么。
> 代码：`pipeline/pristine_binds.py`、`pipeline/harbor.py`、
> `pipeline/pass2fail_verifier.py`。

---

## 1. 一句话

**“恢复”不是另一套机制，它就是“用导出时封好的 tar 重新覆盖可写 bind 源目录”。**

区别只在于：普通 `tar -x` 会保留 tar 里没有的旧文件，所以实现里先删除当前
bind 目录，再解压 tar；这样才是真正的“回到封存时刻”。

---

## 2. 为什么题包会被写脏

公开 Compose 里允许这种可写 bind：

```yaml
services:
  client:
    volumes:
      - ./data:/var/lib/app/data
```

`./data` 不是镜像内路径，而是宿主上的真实目录：

```text
<harbor-runtime-profile>/environment/data/
```

player 容器启动后，往 `/var/lib/app/data` 写文件，实际写进的就是这个宿主
目录。Harbor 销毁 player 容器时**不会**删除或还原 bind 源目录。

于是同一个 `harbor-runtime-profile` 再跑一次时，新的 player 看到的是上一次
留下的文件。如果上一次：

- 把配置改坏了；
- 写了缓存/锁文件；
- 删除了初始化数据；
- 以 root 创建了 uid 65534 不能读的文件；

那么第二次跑题失败，可能不是题本身坏了，而是**题包没有恢复干净**。

这正是两次 Harbor 验收要测的东西：第一次跑完先恢复，第二次在恢复后的题包上
仍然 Pass2Fail，才能说明恢复逻辑有效。

> 只覆盖公开环境里**可写的** `./` **bind**。只读 bind、绝对路径 bind、named
> volume、tmpfs、镜像可写层不在这套机制里；导出合同要求把需要的初始数据
> 转成 `./` bind 或烘进镜像。

---

## 3. 封印：导出时写一次 tar

`create_pristine_binds_tar(task_dir)`：

1. 读 `environment/docker-compose.yaml`；
2. 找出所有可写 `./` bind 源，例如 `./data`、`./conf`；
3. 把它们的当前内容打进 `pristine-binds.tar`，放在 `environment/` 旁边；
4. tar 已存在就**不再重写**，保证整个交付生命周期只有一个“ pristine”版本。

嵌套路径会去重：如果同时有 `./data` 和 `./data/cache`，只封 `./data`，
因为封父目录已经覆盖子目录。

tar 成员有安全检查：拒绝绝对路径、`..`、特殊设备文件，符号链接目标也不能
逃出 `environment/`。

---

## 4. 恢复：删掉当前内容，再解压

`extract_pristine_binds(task_dir, environment)`：

1. 重新读 Compose，算出当前的可写 `./` bind 列表；
2. 对每个 bind 源执行 `_remove()`：文件就 unlink，目录就 `rmtree`；

   遇到 root 拥有的文件时用 `sudo -n rm -rf`；
3. 把 tar 里的成员解压回 `environment/`；
4. 恢复目录和普通文件的 mode（不恢复 owner / mtime）。

为什么先删再解压，而不是 `tar -x --overwrite`：

- player 可能创建了 tar 里根本没有的新文件，`--overwrite` 不会删它们；
- player 可能把目录改成文件、把文件改成目录，覆盖语义会残留旧 inode；
- 先删能保证结果是“封存时刻的精确集合”。

---

## 5. Harbor 的生命周期：为什么需要 wrapper

Harbor 一次 `harbor run` 的顺序是：

```text
harbor run
  ├─ 启动 player（main/client）
  │    └─ player 可写 ./ bind
  ├─ 收集 artifact
  ├─ 销毁 player 环境
  └─ 调用 verifier（--verifier 指定的类）
       └─ verifier 重启 private client+runner，做 Pass2Fail
```

关键点：**player 在 verifier 之前启动。** Harbor 没有“player 启动前调用用户
代码”的 hook。因此：

- verifier 里的恢复，只能保护**下一次**运行，保护不了当前这次 player；
- 要让当前 player 启动前就是干净的，必须在 `harbor run` **进程之外**先恢复。

所谓 **wrapper**，就是一个包住 `harbor run` 的进程：

```text
wrapper:
  extract_pristine_binds()
  subprocess.run(["harbor", "run", ...])
  extract_pristine_binds()
```

两条管线都有这层：

| 管线 | wrapper |
|---|---|
| 新管线内部 | `pipeline/harbor.py::_harbor_run_fresh()` 在 `subprocess.run(harbor ...)` 前后各恢复一次 |
| 新管线外部 | `bin/load_image.py --task <id>` 在加载镜像后、返回前恢复该题 |
| exploit | `orchestrator/export/separate/harbor_package_binds.py` → `call_with_package_bind_restore()` |

所以“player 先于 verifier”是事实，但**不等于“player 只能看到脏 bind”**：
wrapper 在 Harbor 启动 player 之前就已经把 bind 恢复了。

---

## 6. 三层恢复点，各防什么

### 6.1 外层：每次 `harbor run` 前后（wrapper）

`_harbor_run_fresh()`：

```python
extract_pristine_binds(profile, profile / "environment")
try:
    cp = subprocess.run(["harbor", "run", ...])
finally:
    extract_pristine_binds(profile, profile / "environment")
```

- **跑前**：即使上一次进程崩溃、没走到 verifier，也不会把脏字节带进这次
player；
- **跑后**：即使 verifier 没执行或执行失败，题包也会被还原。

这是防“跨 Harbor 运行污染”的主防线。

### 6.2 验收层：两次 Agent run 之间

`accept()`：

```text
export
extract_pristine_binds()   # 第一次前
harbor run #1
extract_pristine_binds()   # 第二次前
harbor run #2
extract_pristine_binds()   # 交付前
```

第二次不是“继承第一次的脏状态”，而是“在恢复后的题包上再跑一次”。如果恢复
逻辑有 bug，第二次会看到第一次的残留并失败。这是验收设计的一部分，不是
额外优化。

### 6.3 verifier 内部：vulnerable / fixed 两个 phase

`Differential.prepare()` 和每个 `phase()` 的 `compose up` 前都会恢复：

```text
prepare()
phase("vulnerable"):
  restore -> compose up -> health -> submission -> oracle -> down
phase("fixed"):
  restore -> compose up -> upload -> solution -> patched_health
          -> same submission -> oracle(exit 1) -> down
```

vulnerable phase 会让 target 写自己的数据目录；fixed phase 必须从干净的
target 开始，否则：

- 官方 patch 可能作用在被污染的文件上；
- `patched_health` 可能被旧状态影响；
- “fixed 不触发”可能变成假阳性/假阴性。

所以 phase 级别的恢复是**同一次验收内部**的正确性要求。

### 6.4 兜底层：verifier 入口/退出和 `fresh_verify` 的 finally

`Pass2FailVerifier.verify()` 在入口和退出时调用 `_restore_public_binds(task_dir)`，
恢复的是 `task_dir/environment` 下的公开可写 bind。`fresh_verify()` 自身也在
`finally` 里再恢复一次，所以直接用 CLI 或在异常路径上跑判分，也不会把题包
留在脏状态。

它的定位是**兜底**，不是主防线：

- 对外部直接调用 Harbor、没有 wrapper 的用户，它至少能保证 verifier 退出后
题包是干净的，下一次运行不会继续累积；
- 但当前 player 已经启动，入口恢复对这次 player 已经太晚。

---

## 7. 为什么不能“Harbor 一启动就自动解压”

因为 Harbor 没有暴露这个 hook。`task.toml` 能控制的是：

- 环境拓扑（`environment_mode`）；
- verifier 类；
- 超时、镜像等。

它没有“player 启动前执行宿主脚本”的字段。verifier 是 Harbor 在 player 销毁
**之后**才调用的。因此只有两种选择：

1. **在** `harbor run` **外面套 wrapper**（本管线和 exploit 的做法）；
2. **每个 trial 用一份全新的 profile 副本**（最彻底，但每次复制题包）。

本管线选 1，因为：

- 两次验收、重试、外部评测都复用同一个 profile；
- 恢复比复制便宜；
- 恢复逻辑本身也需要被验收覆盖。

---

## 8. 外部用户直接跑题时的正确做法

复用同一目录时，最简单是每次跑前执行：

```bash
python3 <bundle>/bin/load_image.py --task <task-id>
```

如果要让 `load_image.py` 直接包住一次 `harbor run`，用 `--run`，它会在
命令前后各恢复一次：

```bash
python3 <bundle>/bin/load_image.py --task <task-id> \
  --run harbor run --path <profile> ...
```

它加载镜像后会恢复该题可写 bind，然后才返回；之后再 `harbor run`。也可以
手动恢复：

```bash
cd <task>/harbor-runtime-profile
PYTHONPATH="$PWD" python3 bin/pristine_binds.py "$PWD"
PYTHONPATH="$PWD" harbor run --path "$PWD" ... \
  --verifier bin.pass2fail_verifier:Pass2FailVerifier
PYTHONPATH="$PWD" python3 bin/pristine_binds.py "$PWD"
```

同一题目目录**不要并发**：两个 player 共用一个 bind 源目录，恢复操作也会
互相踩。不同题目可以并发，因为 `task_dir`、镜像 tag、Compose project 和
IPAM 都是独立的。

---

## 9. 边界与已知限制

1. **只覆盖可写** `./` **bind**。绝对路径 bind、named volume、tmpfs、镜像可写层

   不恢复。导出合同要求需要初始状态的数据用 `./` bind 或烘进镜像。
2. **tar 只封一次**。如果封印之后又修改 Compose 增加新的可写 `./` bind，

   新 bind 不在 tar 里，不会被恢复。
3. **不恢复 owner / mtime**。只恢复目录和普通文件 mode；如果 player 改了

   owner，删除时可能需要 `sudo -n`。
4. **同一 profile 并发不安全**。不是逻辑 bug，是共享目录的天然限制；需要

   并发就复制 profile。
5. **恢复发生在 player 之后的情况**：外部用户直接 `harbor run` 且不套

   wrapper 时，verifier 入口恢复保护不了当前 player；这是第 8 节要求手动
    wrapper 或复制 profile 的原因。
6. **恢复失败不会让当前 trial 直接失败**：wrapper / verifier 的恢复异常会被

   记录或吞掉，以保证判分继续；但下一轮可能看到脏包。排查时看
    `jobs/<name>-restore-error.log`（wrapper）或 verifier evidence。

---

## 10. 代码位置

| 位置 | 作用 |
|---|---|
| `pipeline/pristine_binds.py::writable_bind_rels` | 从 Compose 找可写 `./` bind |
| `pipeline/pristine_binds.py::create_pristine_binds_tar` | 导出时封一次 tar |
| `pipeline/pristine_binds.py::extract_pristine_binds` | 删当前内容并解压 tar |
| `pipeline/pristine_binds.py::main` | 手工恢复 CLI |
| `pipeline/harbor.py::_harbor_run_fresh` | 包住 `harbor run` 的前后恢复（wrapper） |
| `pipeline/harbor.py::accept` | 第一次、第二次运行前显式恢复（循环后不再重复） |
| `pipeline/pass2fail_verifier.py::Differential.prepare/phase` | phase 前后恢复 |
| `pipeline/pass2fail_verifier.py::Pass2FailVerifier.verify` | 公开题包入口/退出兜底恢复 |
| 交付包的 `harbor-runtime-profile/bin/pass2fail_verifier.py` | 同一个通用类的 profile 内副本 |

---

## 11. FAQ

**Q：为啥要恢复？我理解每次开跑前解压覆盖就好了，也不会影响啥。**

A：对，“恢复”就是“解压覆盖”。代码不能自己挑“每次开跑前”这个时机，因为
Harbor 没有 player 启动前的 hook；所以由 wrapper 在 `harbor run` 之前调用
`extract_pristine_binds()`。verifier 里的恢复是 Harbor 内部的 hook，但它在
player 之后，只能保护下一次。

**Q：wrapper 是什么？**

A：一个包住 `harbor run` 的进程/函数：恢复 → 启动 Harbor → 恢复。新管线内部是
`_harbor_run_fresh`；交付包外部是 `bin/load_image.py --task ...`（加载镜像后
恢复，再让用户跑 `harbor run`）；exploit 是 `harbor_package_binds`。

**Q：player 先于 verifier 就是这样的呀？**

A：是，而且正是这个顺序决定了：只在 verifier 入口恢复不够，必须在
`harbor run` 外面先恢复。两者的分工见第 5、6 节。

**Q：既然每次都要解压，为什么不每次复制整个 profile？**

A：可以，而且对外部最稳。复制成本更高；本管线复用 profile 做两次验收和
重试，所以用 tar 恢复，并顺便把恢复逻辑纳入验收。

**Q：第二次验收为什么要先恢复再跑？继承脏状态不是更能发现问题吗？**

A：继承脏状态只能证明“脏了会失败”，不能证明“恢复逻辑能把题包救回来”。
题目交付后会被不同人、不同轮次复用，需要的是后者。恢复后仍 Pass2Fail 才是
可交付状态。