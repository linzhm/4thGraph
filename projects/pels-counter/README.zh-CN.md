# PELS 计数器

[English](README.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

**[构建完整锁](#build)** · [Regtest 入金和复放](#spend-and-verify-on-regtest) · [调整手续费规则](#declare-a-fee-constraint)

4thGraph 把 `advance` 编译到完整合约锁。每次花费只允许一个后继输出，后继的 `u32` 计数加一，并沿用同一段合约代码。[入门版](pels-counter.fth)固定每笔花费的手续费为 1,000 聪。[核心版](pels-counter-core.fth)由花费见证提供后继金额，锁再把金额绑定到实际输出。

<a name="build"></a>

## 构建完整锁

从仓库根目录运行，构建只需要 Python 3.11 或更新版本的标准库。

```sh
export PYTHONPATH=src:.
counter=projects/pels-counter/pels_counter.py
python3 "$counter" build
```

JSON 的 `script_hex` 是计数为 0 的完整锁，`satoshis` 是初始输出金额。Forth 递增词编译为 8 字节，完整锁还要核对实际后继输出。`optimization` 记录了状态转换、编译改写及候选见证的字节成本。

<a name="spend-and-verify-on-regtest"></a>

## Regtest 入金和复放

在 Linux x86-64 上准备 curl、Rust/Cargo 和 C 编译工具链。启动脚本会下载并校验 BSV Node。[Regtest 环境](../../docs/infrastructure.md)

```sh
bash tools/setup-workspaces.sh
export PYTHONPATH=src:.
counter=projects/pels-counter/pels_counter.py
python3 -m venv projects/pels-counter/workspace/venv
. projects/pels-counter/workspace/venv/bin/activate
python -m pip install ecdsa -r tools/requirements-chronicle.txt

report=projects/pels-counter/workspace/build/pels-counter.json
bash tools/verify_node.sh --profile default -- python "$counter" replay --output "$report"
```

复放先为状态 `0` 入金，再把 `0 → 1 → 2` 两笔交易挖入区块。三个状态的输出金额依次是 1,020,000、1,019,000 和 1,018,000 聪。报告保存原始交易、BSV Node 和 chain-gang 的判定以及入块证据。错误计数、不同的后继代码或金额、额外输出以及换了锁定时间却沿用旧见证的交易应被拒绝。加上 `--compare` 可复放所有合格候选。

要单独生成第一笔花费，用 `jq` 从报告读取原始部署交易。输出包含整笔交易的十六进制、输入与输出计数、手续费和交易 ID。

```sh
PYTHONPATH=src:. python3 "$counter" spend --parent "$(jq -r '.deployment.raw' "$report")"
```

<a name="declare-a-fee-constraint"></a>

## 调整手续费规则

在源码写入 `pels-fee: 1000 2000 ;` 可指定闭区间。上下界相同时，编译器直接取该值。上下界不同时，花费者提供手续费，锁验证手续费和扣除之后的后继金额，并承诺整个后继输出。沿用上面的环境，运行有界手续费示例。

```sh
source=projects/pels-counter/pels-counter-bounded-fee.fth
PYTHONPATH=src:. python3 "$counter" --source "$source" build
bash tools/verify_node.sh --profile default -- \
  python "$counter" --source "$source" replay --compare \
  --output projects/pels-counter/workspace/build/pels-counter-bounded-fee.json
```

单独构建花费时可以传入 `spend --parent <raw-tx> --fee 1500`。要让花费者直接指定后继金额，改用核心版并传入 `--amount <satoshis>`。[核心版的复放命令与见证细节](README.md#compare-the-core-pels-rule)
