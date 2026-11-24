# CCTP 双父 Groth16 递归实验

实验用现有 CCTP 1→2 Circom 关系分别为两笔拆分出证。两个父各自消费不同的 outpoint，输出分别为 640/384 和 700/324。准备程序构造带持有人签名和验证器见证的父交易。可用时，chain-gang 检查两笔完整交易。候选子交易分别花费第一个父的 vout 0 和第二个父的 vout 1，合计 964，输出 700/264。

Go 程序将固定的 BLS12-381 父验证密钥编译进外层 BLS12-381 Groth16 电路。电路固定两个父共享的版本、资产身份和验证器身份前缀，重算父语句的双 SHA-256，按两个大端 128 位值执行 Groth16 验证。两个父证明使用相同的电路和不同的验证输入。验证包含证明点的子群检查和完整点运算。外层只公开两个大端 128 位值，其字节编码为：

```text
SHA256d("BSV/CCTP/recursion-spike/v1\0" || candidateCommitment32
        || SHA256d(parentStatement0) || SHA256d(parentStatement1))
```

`candidateCommitment32` 是宿主从真实交易线格式的 MIMO 候选构造并提交的摘要。外层约束它与两份父证明语句的有序关系。BSV 上实际子交易的认证、两份父语句与该交易实际消费 outpoint 的认证，以及合法铸造起点仍是集成工作。实验使用来自公开测试参数的 Groth16 父证明和测试密钥。切换到真实参数需要审计和独立可信设置。

## 复现

从仓库根目录运行。需要 Circom、Node.js、Go 1.26.8 或更新版本，以及原 CCTP Python 依赖。

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference \
  ../cctp-test-tools/venv/bin/python projects/cctp/recursion/prepare.py /tmp/cctp-recursion-input.json
cd projects/cctp/recursion
go run . /tmp/cctp-recursion-input.json
go run . -prove -setup-dir /tmp/cctp-recursion-parameters \
  -artifact /tmp/cctp-recursion-proof.json /tmp/cctp-recursion-input.json
```

基础命令编译并执行约束求解，使用独立随机值代替 BSB22 承诺产生的挑战。这只提供 R1CS 可解性证据。`-prove` 另外进行临时 Groth16 设置、生成外层证明，再用 gnark 原生验证器验证。准备程序在输出 JSON 中记录内层约束数、生成时间、父 txid 和 chain-gang 是否实际执行。

仓库的 `testdata/two-parents.json` 可替换临时输入文件，重跑外层约束检查。此例外层有 4,246,284 条 R1CS 约束，包含一个 BSB22 承诺，参与挑战的公开线索引为空。Apple Silicon 工作机上带签名样例的编译和有效求解分别用时约 13.2 秒和 1.7 秒。内层每份证明来自 1,598,409 条约束。两份父交易各自通过 chain-gang。

一次不同父语句的完整外层实验使用相同约束结构和无签名合成父交易，临时设置用时 12 分 6.9 秒，外层出证 28.9 秒，gnark 原生验签 2.6 毫秒，最大驻留内存约 12.34 GB。生成的证明实际包含一个承诺，外层验证密钥有四个 IC 点。

`-setup-dir` 在设置完成后保存两个密钥和精确约束系统指纹。更换父交易、输出数量、父证明或子交易摘要时，同一编译约束可复用同一路径。首次运行时参数目录须尚未存在。重用时验证器重新编译并拒绝指纹不匹配的目录。当前电路把资产身份和父验证器身份都固化在编译常量里，资产锚点变化会使缓存失效。后续版本可把资产作为两个父语句与子语句共用的见证，并在电路内重算子语句摘要。BSV 从候选交易和父材料重算的摘要将继续绑定这三个语句。父证明验证密钥仍作为固定配置。

负例直接改动外层私有输入，覆盖不同父的真证明、原公开输入下替换当前承诺、重算公开输入后篡改父语句，以及复制同一父语句和证明。最后一例限定当前实验的独立父路径。同一父交易的不同 vout 应由正式关系单独覆盖并按 outpoint 判重。

## 独立 BSV 验证器检查

`committed_verifier.py` 复用原 Groth16 Script 验证器并检查 BSB22 承诺。它用同一承诺点计算短 MiMC 挑战、验知识证明配对，并计入 Groth16 公开输入点。`recursive_digest_script()` 从三个已认证的摘要重算 Go 端同样的公开输入。调用方负责认证这三个摘要。

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  ../cctp-test-tools/venv/bin/python -m unittest -v \
  test_committed_verifier test_pedersen test_short_mimc test_parent_preimage
```

自带的小型 gnark BSB22 证明测试了整个 Script 验证器。测试在重算见证后仍拒绝改写的公开值和知识证明。设置 `CCTP_BSB22_ARTIFACT=/tmp/cctp-recursion-proof.json` 可使用 `-artifact` 导出的任意同形状证明，运行同一完整输入检查。配合 `CCTP_BSB22_INPUT=/tmp/cctp-recursion-input.json` 时，测试从该输入文件的摘要材料在 Script 内重建公开输入。

独立 Bitcoin SV Node 1.2.3 在高度 205 接受小型证明，区块 `31c03368ed775d87e6da58f5c4b225e95fc572784f6442d52d4d1c869f93638c`，交易 `d0ce06ce89a4fe38bdfd01599cac9d71a8dd9e1fa2fa3ed21825479fa779f683`。错误知识证明在资金仍未花费时以 mandatory-script-verify-flag-failed 拒绝。锁 931,095 字节，消费见证 1,959 字节。默认 500,000 字节脚本政策拒绝有效消费，调高隔离节点的 `maxscriptsizepolicy` 至 2,000,000 后入块。复现时可指定 `REGTEST_COOKIE` 和 `REGTEST_URL` 使用带 txindex 和 Chronicle 的回环节点。这条节点记录使用验证器测试证明，当前实际递归交易仍待联测。

## 接入约束

- **验证密钥闭环。** 目前外层固定的是已有的内层密钥，只能叠加一层。把由外层设置生成的自身密钥当成当前电路编译常量会循环依赖。候选办法是把结构固定的自验证密钥作为电路见证，在电路中重算规范密钥承诺，并由资产认可的 BSV 锁固定承诺值。递归父子的公共语句必须继承同一承诺，铸造分支使用独立授权的基例；密钥布局、曲线点与承诺验证参数都应纳入身份。动态 G2 预计算不能由见证自由控制。
- **父材料认证。** `parent_preimage.py` 从 1→2 父交易原文重建紧凑 ForkID preimage，验证输入 0 的前序 outpoint 和锁，并从该前序输出读取 satoshi 金额。其 Script 与宿主编码一致，输出顺序、前序金额替换和错误验证器负例通过。接入时由子交易从实际 prevouts 认证父 txid 和 vout，再用这段 Script 推导父语句并绑定到公开承诺。证明只绑定自己的 ForkID 语句，因此最终 txid 仍需由子交易认证。
- **证明接入范围。** BSV 扩展支持一个有限 G1 承诺点、一个有限 G1 知识证明和无公开索引的短 MiMC。最终递归电路若改变承诺结构，必须匹配新的布局和哈希字段。独立节点仍需在真实 MIMO 交易中认证三个摘要，并验证来自同一外层产物的证明。

参考实现为 [gnark v0.16.5 递归验证器](https://github.com/Consensys/gnark/blob/v0.16.5/std/recursion/groth16/verifier.go)、[非原生域的挑战约束](https://github.com/Consensys/gnark/blob/v0.16.5/std/math/emulated/field_mul.go) 和 [BLS12-381 Groth16 原生验证器](https://github.com/Consensys/gnark/blob/v0.16.5/backend/groth16/bls12-381/verify.go)。该版本包含 [BLS12-381 标量乘法的安全修复](https://github.com/Consensys/gnark/releases/tag/v0.16.5)。
