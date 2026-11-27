# 安装 4thGraph

[English](install.md) · [文档索引](README.zh-CN.md)

在终端、CI 或脚本中使用 CLI。将 Agent Skill 装入 Codex 后，可用它编写 Forth、编译和检查构建结果。

## CLI

在 macOS 或 Linux 上使用 Python 3.11 或更高版本。从 4thGraph 仓库根目录运行。

```sh
python3 tools/install.py
export PATH="$HOME/.local/bin:$PATH"
4thgraph --version
4thgraph --capabilities
```

安装器将 `4thgraph`、`4thgraph-report`、`4thgraph-circuit` 和 `4thgraph-verify` 写入 `~/.local/bin`。用 `--prefix /path/to/prefix` 可指定安装目录。命令打包编译器模块、标准库源码和共享 Python 依赖。只构建 Script 和 Circom 源码时，在仓库外使用 Python 即可。使用 Circom 或 snarkjs 构建证明还需要 Node.js 和 npm。要升级，从所需的仓库提交重跑安装器。要卸载，从所选前缀的 `bin` 移除四个命令。

从仓库根目录编译示例词，查看栈签名、字节码和改写记录。

```sh
4thgraph projects/workflow-examples/example.fth --entry inc --optimize safe
```

构建交易计划需要 Forth 源码、签名角色到压缩 secp256k1 公钥的 JSON 映射，以及 32 字节十六进制任务 ID。将 `TASK_ID` 设为本次构建的任务 ID 后运行。

```sh
4thgraph contract.fth --mode auto --target both --explain \
  --keys keys.json --task-id "$TASK_ID" > build.json
```

`--mode fused` 要求部署后只花费一次，`--mode split` 允许工作阶段独立提交。把保存的复放转换为决策报告。

```sh
4thgraph-report replay.json --output-dir decision
```

CLI 和 skill 使用同一份仓库检出。`4thgraph-circuit` 生成 Circom，`4thgraph-verify` 构建 `relation:`。有资金复放使用仓库的 regtest 工作流、BSV Node 和锁定版本的 chain-gang。 [复放与编译](toolchain.md#复放与编译) · [语法书](language/syntax.md) · [验证路径](language/stdlib.zh-CN.md)

分阶段工作流用 `4thgraph cpn --help` 查看命令。`plan` 比较交易布局与阶段证明后端，`tune` 比较编译优化级别，`replay` 与 `verify` 分别生成和核验入金复放回执。 [CPN 实操指南](../skills/4thgraph/references/cpn.zh-CN.md)

使用 SDK 或 Python API 进行开发时，从仓库安装 Python 包。

```sh
python -m pip install -e .
```

运行 `bash tools/setup-workspaces.sh` 初始化本地构建、缓存和日志目录。

## Codex Agent Skill

在 4thGraph 仓库中把 skill 目录复制到用户的 skill 路径。

```sh
mkdir -p "$HOME/.agents/skills"
cp -R skills/4thgraph "$HOME/.agents/skills/"
```

也可复制到单个应用仓库的 `.agents/skills/`。在 Codex 中调用 `$4thgraph`，提供 Forth 源码或需求。例如，请它分别构建同一源码的融合与拆分版本，并解释不同的交易边界。Skill 可以用已安装的 CLI，也可以从工作区运行编译器。若未看到 skill，重新加载 Codex。 [Codex skill 发现机制](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)

编写和优化细节见 [skill 工作流](../skills/4thgraph/SKILL.md) · [语言规范](language/specification.md)。
