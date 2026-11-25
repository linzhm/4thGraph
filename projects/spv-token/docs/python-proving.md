# BSV SPV Token 的 Python 出证与标准参数

CCTP 从实际交易构造公开声明和私有输入，Python 生成 snarkjs `.wtns` v2。通用 Python prover 读取普通 BLS12-381 Groth16 `.zkey` 和 `.wtns`，在 Metal 上做 NTT，使用 arkworks 完成曲线运算和验真。BSV 验证器使用该 `.zkey` 内的验证密钥。组件验收用 chain-gang 检查完整输入，并由独立 BSV regtest 节点确认。完整生命周期的标准参数与重新入块另行验收。 [通用出证器](../../groth16/reference/python_prover.py) · [完整输入检查](../../../shared/chain_gang.py)

## 电路设置与验证密钥

例如，以下命令创建冻结与解冻共用的普通 BLS12-381 Groth16 参数。令 `CCTP_PTAU` 指向经过验证、容量至少为 `2^18` 的 BLS12-381 第一阶段参数。隔离 regtest 的贡献和密钥用于测试。

```sh
cctp_build=$(mktemp -d)
circom projects/spv-token/circuits/freeze_transition.circom --prime bls12381 --r1cs --wasm -o "$cctp_build"
snarkjs groth16 setup "$cctp_build/freeze_transition.r1cs" "$CCTP_PTAU" "$cctp_build/initial.zkey"
snarkjs zkey contribute "$cctp_build/initial.zkey" "$cctp_build/freeze.zkey" --name "CCTP phase 2"
snarkjs zkey verify "$cctp_build/freeze_transition.r1cs" "$CCTP_PTAU" "$cctp_build/freeze.zkey"
snarkjs zkey export verificationkey "$cctp_build/freeze.zkey" "$cctp_build/verification_key.json"
```

同一套命令也适用于 [拆分电路](../circuits/split_commitment.circom) 和 [守恒电路](../circuits/conservation.circom)。拆分要求 `2^18`，守恒要求 `2^19`。将新密钥配置给新测试发行锚的验证器。旧锁内的验证密钥约束对应旧策略的花费。 [snarkjs 官方设置流程](https://github.com/iden3/snarkjs#15-setup)

复用 Cardano PPOT 时，先用 `snarkjs powersoftau verify` 验证所选 `.ptau`，将其中的最终贡献和 beacon 对照公布的仪式记录，再为 CCTP 的 `.r1cs` 做专属第二阶段。2026-11-25 实测 `2^22` 下载支持范围请求，`2^23` 的公开链接返回 403。`2^22` 可用于现有 3,433 B 代币父检查点电路，完整生命周期需要更大的参数或更小的电路。 [Cardano 参数表](https://github.com/p0tion-tools/cardano-ppot#prepared-and-truncated-files) · [公布的 beacon 记录](https://github.com/p0tion-tools/cardano-ppot/blob/main/0041_beacon/pot23_beacon_record.txt)

本机使用的 Cardano `2^18` 文件 SHA-256 为 `5e14d0c7d096592a2ced33a8a8a331ca9ded1f805f78c1d4cd637aad28b15ab4`。原版 snarkjs 0.7.6 已验证其中的贡献链、保留的幂及 Lagrange 段。41 轮记录中的最终 challenge 摘要和 beacon 字段与发布记录一致。拆分电路的 `.zkey` 通过 `zkey verify`，Python 生成的已入块证明通过 `groth16 verify`。截短文件的验证覆盖保留的参数，整份仪式最终 challenge 的全量哈希检测需要 `2^23` 原档。 [验收记录](../fixtures/python-snarkjs-regtest.json) · [snarkjs 校验源码](https://github.com/iden3/snarkjs/blob/v0.7.6/src/powersoftau_verify.js)

## Python 入口

从仓库根目录运行。Python 环境包含 chain-gang、`wasmtime`、`wgpu` 和 `py-arkworks-bls12381`。令 `CCTP_NTT_SHADER` 指向 [通用出证器锁定指纹的 WGSL 文件](../../groth16/docs/toolchain.md#python-prover-with-metal-transforms)。

```sh
export PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion
python3 projects/spv-token/recursion/run_freeze_split_regtest.py \
  --zkey "$cctp_build/freeze.zkey" --wasm "$cctp_build/freeze_transition_js/freeze_transition.wasm" \
  --ntt-shader "$CCTP_NTT_SHADER" --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --out "$cctp_build/freeze-test"

python3 projects/groth16/reference/python_prover.py \
  --zkey "$CCTP_ZKEY" --wtns "$CCTP_WTNS" --ntt-shader "$CCTP_NTT_SHADER" --out proof.json
```

## 完整生命周期

同一份已验收关系已导出标准 `.r1cs`。Python 读取离线赋值规则，按原线序生成标准见证。该关系有 **13,787,986** 条约束、**12,061,957** 根线和两个公开输入。完整新密钥需要容量至少为 `2^24` 的 BLS12-381 Groth16 第一阶段材料。Cardano 公布的已准备参数列表止于 `2^23`。 [Cardano 参数列表](https://github.com/p0tion-tools/cardano-ppot#prepared-and-truncated-files)

完整生命周期的九个归档动作通过了 Python 约束检查。换一个真实父交易字节的负例被拒。新的生命周期 `.zkey` 和重新入块仍待第一阶段参数。 [生命周期入口和验收](two-slot-lifecycle.md)

## 父交易检查点

两类父检查点已使用标准 Circom 电路。332 字节的 [普通父检查点](../circuits/parent_checkpoint.circom) 要求 `2^19`。3,433 字节的 [代币父检查点](../circuits/token_checkpoint.circom) 已用 Cardano `2^22` 跑通。snarkjs 验证 `.ptau`、从本次标准 `.r1cs` 生成的初始密钥、第二阶段贡献、Python 生成的 `.wtns` 和最终证明。独立 BSV Node 1.2.3 在高度 321 确认代币结转，并拒绝改数量、错持有人、错中间态和错后缀。 [验收记录](../fixtures/python-snarkjs-regtest.json)

M1 Max 的 Python 出证耗时 602 秒，含见证生成 641 秒。检查点的父披露和证明共 2,691 B，原文对照披露为 3,436 B。计入验证器资金与结转交易，两组分别为 908,276 B 和 9,036 B。这个样本的差额主要来自 Groth16 验证器脚本及其交易材料。 [字节和耗时记录](../fixtures/python-snarkjs-regtest.json)
