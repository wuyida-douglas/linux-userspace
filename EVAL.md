# 单题跑题 / 评测

只说明怎么评测一个已发布的题包。批量调度和合成见
`/nvme/wuyida/新管线开发/README.md`。

## 1. 前置条件

- Docker + Docker Compose
- Harbor **0.22.0**，且在 `PATH`
- 本机 `claude` 可执行文件
- 模型环境文件，默认 `/nvme/wuyida/env`：

```text
ANTHROPIC_BASE_URL=...
ANTHROPIC_API_KEY=...        # 或 ANTHROPIC_AUTH_TOKEN
```

## 2. 一键评测

脚本：`/nvme/wuyida/新管线开发/scripts/evaluate.sh`

```sh
# ===== 直接改这里 =====
BUNDLE=/nvme/wuyida/新管线开发/harbor_export/20261111-production
TASKS="cve-2024-23346-file-pov"
ENV_FILE=/nvme/wuyida/env
MODEL=glm-5.3
MAX_TURNS=300
EVAL_JOBS=/nvme/wuyida/新管线开发/eval-jobs
CLAUDE_BIN=
CLAUDE_VERSION=
HARBOR_BIN=harbor
# ======================
```

运行：

```bash
/nvme/wuyida/新管线开发/scripts/evaluate.sh
```

- `TASKS` 是空格分隔的 task id 列表，可以写多个。
- `CLAUDE_BIN` 留空时自动从 `PATH` 查找 `claude`；`CLAUDE_VERSION` 留空时
  自动执行 `claude --version` 取版本。
- 临时覆盖也可以带参数：`evaluate.sh <bundle-dir> [task-id...]`。

脚本会：

1. 用 `<bundle>/bin/load_image.py --task` 加载本题镜像；
2. 恢复 `harbor-runtime-profile/environment` 的可写 bind；
3. 用 `load_image.py --run` 包住 `harbor run`，跑题前后再恢复一次；
4. 自动设置 `PYTHONPATH`；
5. 只挂本机 `claude`，不挂参考 PoC；
6. 把结果写到 `/nvme/wuyida/新管线开发/eval-jobs/<job-name>/`。

也可以直接设置 `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` /
`ANTHROPIC_BASE_URL`，不依赖环境文件。

## 3. 手动跑（不用脚本）

```bash
cd /nvme/wuyida/新管线开发/harbor_export/20261111-production/cve-2024-23346-file-pov/harbor-runtime-profile
PYTHONPATH="$PWD" /usr/local/bin/harbor run \
  --path "$PWD" \
  --agent claude-code \
  --model glm-5.3 \
  --ak max_turns=300 \
  --ak version=<claude-version> \
  --mounts '[{"type":"bind","source":"<claude-binary>","target":"/usr/local/bin/claude","read_only":true}]' \
  --ae ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  --ae ANTHROPIC_BASE_URL="$ANTHROPIC_BASE_URL" \
  --n-attempts 1 \
  --jobs-dir /nvme/wuyida/新管线开发/eval-jobs \
  --job-name <unique> --yes \
  --verifier bin.pass2fail_verifier:Pass2FailVerifier \
  --verifier-timeout-multiplier 6.0
```

`--verifier` 不是 `--verify`。`PYTHONPATH` 必须指向 profile，否则 Harbor
找不到 `bin.pass2fail_verifier`。`task.toml` 不写 `import_path`，也不写超时。

## 4. 看结果

```text
/nvme/wuyida/新管线开发/eval-jobs/<job-name>/.../result.json
```

重点看：

```json
{"verifier_result": {"rewards": {"reward": 1.0}}}
```

- `1.0`：vulnerable 触发、fixed 不触发、patched 健康；
- `0.0`：agent 没做对 / fixed 仍触发；
- 没有 reward 或 trial exception：判分没完成（镜像、target、oracle、patch
  等基础设施/题目问题），不是 agent 的 0 分。

## 5. 常见错误

| 现象 | 原因 |
|---|---|
| `unrecognized arguments: --verify` | 参数是 `--verifier` |
| `ModuleNotFoundError: bin.pass2fail_verifier` | 没设 `PYTHONPATH`，也没用 `load_image.py --run` |
| main 里没有 `claude` | 忘了 `--mounts` 挂本机 claude |
| 适配器尝试联网安装 | `--ak version` 和挂载 binary 版本不一致 |
| shared 镜像不存在 | 先 `python3 /nvme/wuyida/新管线开发/harbor_export/20261111-production/bin/load_image.py --shared-only` |
| 模型 API 连不上 | `ANTHROPIC_*` 没设置，或 Compose 里写死了代理 |
| 第二次跑看到上次残留 | 没用 `load_image.py --task` / `--run` 恢复 bind |