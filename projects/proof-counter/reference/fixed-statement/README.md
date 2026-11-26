# BSV 上的 BLS12-381 Groth16 验证器对照

在同一份 BLS12-381 Groth16 固定声明测试中，4thGraph 的部署和一次花费合计 **280,731 B**，比受测 nChain 配置少 **28.7%**。同一 BSV Node 上的验证 RPC 中位耗时低 **43.9%**。两版都验证了同一份证明并实际入块。

## 实测结果

| 指标 | nChain | 4thGraph |
|---|---:|---:|
| 锁定脚本（含相同授权逻辑） | 372,236 B | 279,463 B |
| 解锁见证前缀 | 21,012 B | 963 B |
| 完整解锁脚本（含签名） | 21,084 B | 1,035 B |
| 部署交易 | 372,372 B | 279,599 B |
| 花费交易 | 21,181 B | 1,132 B |
| 部署加一次花费 | 393,553 B | 280,731 B |
| BSV Node 验证 RPC 中位数 | 202.67 ms | 113.76 ms |
| chain-gang 验证中位数 | 71.90 ms | 27.67 ms |

[原始结果和交易 ID](../../versions/v0.1.0/measurements.json)

## 两版验证了什么

- 两边使用同一把验证密钥、同一份 Circom 证明和相同的五个公开信号。公开信号在部署时固定。两边启用相同的 BIP143 ALL 所有者签名检查，并使用 v2 交易。
- nChain 使用仿射坐标的预计算 MSM 入口。测试把由公开信号得到的 MSM 点放进锁，配对梯度放在解锁脚本，取模阈值为 1,600 位（200 B）。解锁数据还携带证明点和 Miller loop 结果的逆元。
- 4thGraph 在构建时预计算与公开信号有关的固定配对项。解锁前缀是单个数据包，含证明点和配对余数见证。证明格式、曲线和声明一致，两版的 Script 辅助见证各自编码。
- 两版均接受有效证明，在 BSV Node 1.2.3 regtest 入池并挖块。使用同一把密钥、但对应另一组公开信号的有效证明时，两版在 BSV Node 和 chain-gang 都拒绝。耗时是每个引擎七次验证的中位数，节点值含 RPC 开销。
- 结果适用于本夹具和受测 nChain 配置。nChain 的通用入口支持花费时提供公开输入。将固定点梯度移入锁、使用投影坐标入口或调整取模阈值，都属于其他配置。

[测试专用证明夹具](../../versions/v0.1.0/bls12381-counter.json) · [4thGraph 生成器](../../../../src/fourthgraph/verification/bls12381/verifier.py) · [nChain Groth16 生成器](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/groth16/model/groth16.py)

## 复现

准备 Python 3.12 和 BSV Script Lab 的复放环境。chain-gang 使用项目已固定的 `tx-engine` 提交 `74676b9c002c452e7f21a9ed9265f4972bef03f6`。从 BSV Script Lab 根目录运行下面的命令。4thGraph verifier 的对照版本为 `6cf3e89`。

```sh
lab=$(pwd)
bench="$lab/projects/proof-counter/reference/fixed-statement"
fixture="$lab"/projects/proof-counter/versions/v0.1.0/bls12381-counter.json
scratch=$(mktemp -d)
git clone https://github.com/nchain-innovation/zkscript_package "$scratch/nchain"
git -C "$scratch/nchain" checkout --detach fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4
git -C "$scratch/nchain" apply "$bench/nchain-stack.patch"

(
  cd "$scratch/nchain"
  python3.12 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  PYTHONPATH=src:. .venv/bin/python "$bench/prepare_nchain.py" "$fixture" "$scratch/scripts"
)

PYTHONPATH="$lab/src:$lab" bash tools/verify_node.sh --profile raised -- \
  python "$bench/replay_comparison.py" "$fixture" "$scratch/scripts"
```

复放脚本在输出目录生成 `same-proof-replay.json`。附带的 nChain 补丁合并相邻的两次 `OP_DROP`，重现本次实测用的 nChain 构建。原始结果记录交易 ID 和耗时，重跑时这些字段会随节点和钱包变化。DER 签名长度可使完整解锁脚本或交易字节数轻微浮动。本次复跑的两个锁和两个见证前缀均精确复现，4thGraph 的花费因签名长 1 B 为 1,133 B。
