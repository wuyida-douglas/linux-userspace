# 单题跑题 / 评测

本文只说明**一道题**怎么在 Harbor 里跑。批量、并发和调度不在本文范围。

假设交付包解压在：

```text
<bundle>/
├── bin/load_image.py
├── shared-images/
└── <task-id>/
    ├── image-lock.json
    ├── images/
    └── harbor-runtime-profile/
```

Harbor 版本要求 **0.22.0**；宿主机需要可用的 Docker，且 `harbor` 在 `PATH` 中。

---

## 1. 加载镜像

在 bundle 根目录执行：

```bash
python3 bin/load_image.py --task <task-id>
```

它会：

- 按 `<task-id>/image-lock.json` 加载本题和共享镜像；
- 校验 tar 的 `sha256` 和加载后的 image ID；
- 在返回前恢复本题 `harbor-runtime-profile/environment` 下的可写 bind。

如果本题没有可写 bind，最后会打印 `restored writable binds ...: False`，这是正常的。

---

## 2. 跑题

**注意不是 `harbor run --verify XXX`，而是 `--verifier ...`。**

推荐直接用 `load_image.py --run` 包住 `harbor run`：它会在跑题前恢复一次、
跑题结束后再恢复一次，并自动把 profile 加进子进程的 `PYTHONPATH`。

```bash
cd <bundle>/<task-id>/harbor-runtime-profile

python3 <bundle>/bin/load_image.py \
  --task <task-id> \
  --root <bundle> \
  --run harbor run \
    --path "$PWD" \
    --agent claude-code \
    --model glm-5.3 \
    --ak max_turns=300 \
    --ak version=2.1.228 \
    --mounts '[{"type":"bind","source":"<claude-binary>","target":"/usr/local/bin/claude","read_only":true}]' \
    --ae ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
    --ae ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL}" \
    --n-attempts 1 \
    --jobs-dir jobs \
    --job-name "<unique-job-name>" \
    --yes \
    --verifier bin.pass2fail_verifier:Pass2FailVerifier \
    --verifier-timeout-multiplier 6.0
```

参数说明：

| 参数 | 说明 |
|---|---|
| `--path` | 指向本题的 `harbor-runtime-profile` |
| `--agent claude-code` | 让 Harbor 启动 Claude Code 做题，不是 oracle |
| `--model` | 做题模型；按评测需要改 |
| `--ak max_turns=300` | 单次尝试的最大轮数 |
| `--ak version=2.1.228` | 必须和挂载的 `claude` binary 版本一致，否则适配器会尝试联网安装 |
| `--mounts` | 把本机 `claude` 可执行文件只读挂进 main；`<claude-binary>` 换成实际路径 |
| `--ae` | 模型 API 凭据；不要写进 Compose 或题包 |
| `--jobs-dir` | Harbor 结果目录 |
| `--job-name` | 本次运行名，单题内唯一即可 |
| `--verifier` | 本题的通用 Pass2Fail verifier 类 |
| `--verifier-timeout-multiplier` | 题包里不写超时；这里给 verifier 留足时间（默认 600s × 6） |

**评测时不要挂参考 PoC。** 合成阶段末尾的自动验收会额外把
`tests/private/reference_*` 挂到 `/workspace` 当作“已经写好的提交”；那是验收
流程，不是评测 agent。上面的命令只挂 `claude` 二进制。

---

## 3. 不想用 `--run` 时

也可以分成两步：

```bash
python3 <bundle>/bin/load_image.py --task <task-id>

cd <bundle>/<task-id>/harbor-runtime-profile
PYTHONPATH="$PWD" harbor run \
  --path "$PWD" \
  --agent claude-code \
  --model glm-5.3 \
  --ak max_turns=300 \
  --ak version=2.1.228 \
  --mounts '[{"type":"bind","source":"<claude-binary>","target":"/usr/local/bin/claude","read_only":true}]' \
  --ae ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  --ae ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL}" \
  --n-attempts 1 \
  --jobs-dir jobs \
  --job-name "<unique-job-name>" \
  --yes \
  --verifier bin.pass2fail_verifier:Pass2FailVerifier \
  --verifier-timeout-multiplier 6.0
```

`PYTHONPATH` 必须指向 `harbor-runtime-profile`，否则 Harbor 找不到
`bin.pass2fail_verifier`。`task.toml` 不写 `import_path`，verifier 只通过
`--verifier` + `PYTHONPATH` 加载。

---

## 4. 看结果

结果在：

```text
jobs/<job-name>/
```

重点看 trial 的 `result.json`：

```json
{
  "verifier_result": {
    "rewards": {"reward": 0.0}
  }
}
```

- `reward = 1.0`：agent 的提交在 vulnerable 上触发、在 fixed 上不触发，且
  patched 正常；
- `reward = 0.0`：agent 没提交、提交不对、或者 fixed 仍触发；
- 没有 reward / trial exception：判分没有完成（target 起不来、oracle 异常、
  patch 失败等），不是 agent 的 0 分。

单题跑题不需要看 `acceptance.json`；它只是合成阶段两次验收的证据副本。

---

## 5. 常见错误

| 现象 | 原因 |
|---|---|
| `unrecognized arguments: --verify` | Harbor 参数是 `--verifier`，不是 `--verify` |
| `ModuleNotFoundError: bin.pass2fail_verifier` | 没设 `PYTHONPATH`，且没有用 `load_image.py --run` |
| main 里没有 `claude` | 忘了 `--mounts` 挂载本机 `claude` 二进制 |
| 适配器尝试联网安装 Claude Code | `--ak version=` 和挂载 binary 的 `--version` 不一致 |
| 所有题都是 0 或没有 reward | 没传 `--verifier`，Harbor 回退到 `tests/test.sh`；该脚本在 separate 模式下不判分 |
| 模型 API 连不上 | 没传 `--ae ANTHROPIC_API_KEY` / `ANTHROPIC_BASE_URL`，或 Compose 里写死了代理 |
| 第二次跑题看到上一次的残留 | 没有用 `load_image.py --task` / `--run` 恢复可写 bind |