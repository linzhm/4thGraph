# P-256 script size comparison · P-256 脚本体积对照

[Matched v0.2.0 arithmetic comparison](scrypt-matched.en.md) · [v0.2.0 同算法对照](scrypt-matched.zh-CN.md)

A funding output carries the complete locking script. The table measures serialized Bitcoin Script bytes, beginning at the first opcode, for the same public P-256 key, signature and digest. Unlock sizes include push opcodes. The comparison uses a single [published payment vector](../versions/v0.1.0/spend-all.json).

每个收款输出都包含完整锁定脚本。下表从第一个 opcode 数起，解锁字节数含推送指令。三者使用同一组公开的 R1 公钥、签名和摘要。

| Script | Locking script (bytes) | Unlocking script (bytes) |
|---|---:|---:|
| Upstream sCrypt R1 test, eight public methods | 4,485,650 | 168 |
| sCrypt R1 control, only `verifySig` | 2,248,716 | 166 |
| P2PKH-R1 payment, BIP143 ALL vector | 59,582 | 326 |

For the single-method comparison, each P2PKH-R1 output carries **2,189,134 fewer locking-script bytes (97.35%)**. The payment vector supplies 160 more bytes at spend time. Counts exclude transaction framing such as CompactSize script lengths.

以单方法版本作对照，P2PKH-R1 每个输出少写 2,189,134 字节的锁定脚本。花费时，本例多提供 160 字节的解锁数据。表中只统计脚本本身。

### What was compiled · 编译口径

- **Upstream test contract.** An unchanged checkout of sCrypt's eight-method `SECP256R1Test` exposes point arithmetic, modular inversion and signature verification. We call `verifySig(digest, signature, point, true)`. [Upstream source](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/tests/contracts/heavy/secp256r1.ts)
- **Verify-only control.** Our wrapper exposes one method that asserts the result of the same upstream verifier. Both harnesses receive a digest and a point supplied by the caller. The caller selects the key and digest for these standalone verification tests. [Wrapper](https://github.com/linzhm/bsv-script-lab/blob/f278c5c64d6de94a3dd3300c858f4747576d31c7/research/scrypt-compare/verifyOnly.ts)
- **P2PKH-R1.** The wallet supplies the input signing preimage, key, raw signature, inverse and derived selector. The lock checks the owner hash, verifies R1 and binds the authorization to the actual input. The selected spend uses BIP143 ALL. [Wire specification](spec.en.md)

上游原版含八个公开测试方法。单方法对照由本项目编写，只保留一次上游 R1 验签调用。两个 sCrypt 调用都直接接收摘要。P2PKH-R1 还执行所有者检查和交易绑定，因此解锁数据也包含原像等字段。

### Optimizations · 优化设置

We checked out scrypt-ts-lib at `fc71404fb82bc513dba3908bf47fc231a169787c`, installed dependencies from its lockfile, transpiled the library with `scrypt-cli@0.2.3 compile --asm --noArtifact` and compiled the selected harness with scryptc `1.20.0+commit.693498a`. The CLI requests `optimize: true` for the contract artifact. The comparison audit checks the generated R1 library against the upstream inline ASM overrides for `modInverseBranchlessN`, `modInverseBranchlessP` and `modInverseEGCD`. [Upstream overrides](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/.asm/asm.json) · [CLI compilation path](https://github.com/sCrypt-Inc/scrypt-cli/blob/73ec1f73263d2c8296bd96fa4f7cb72c5d4d1a24/src/lib/compile.js)

`--noArtifact` 只用于上游库的转译阶段。最终测试合约单独编译时启用了产物优化。核验包括上游给 R1 配置的三段 ASM。数字代表这两个具体构建。定制 sCrypt 合约可以选择其他坐标系、窗口算法或验算提示，结果需要单独测量。

### Validation and interpretation · 验证与解读

The default script-size policy rejected the eight-method script with `Script is too big`. For the joint replay we set `-maxscriptsizepolicy=6000000` and raised validation time limits. BSV Node 1.2.3 accepted all three scripts via `verifyscript` on regtest using explicit synthetic previous outputs. This run tested the published positive vector. [Initial policy result](https://github.com/linzhm/bsv-script-lab/actions/runs/44394599741/job/135121010618) · [Joint replay](https://github.com/linzhm/bsv-script-lab/actions/runs/44396510649/job/135127731821)

原版八入口合约在初次测试中触发节点的脚本大小策略。统一复测时将策略上限设为 6,000,000 字节并放宽验算时限，三个脚本均通过同一测试向量。

At the same per-byte fee rate a smaller lock reduces the size-dependent cost of creating the output. Total transaction fees depend on all inputs and outputs and miner policy. These harnesses have different interfaces, so the size ratios do not measure language efficiency.

费率相同时，新建输出少写的脚本字节可以直接节省按字节计的费用。实际总费用还取决于整笔交易和矿工策略。这组结果用于比较指定实现，不能外推为所有 sCrypt 钱包的体积。

[Eight-method compilation and scripts](https://github.com/linzhm/bsv-script-lab/actions/runs/44395521127/job/135124238197) · [Optimization audit, single-method build and replay](https://github.com/linzhm/bsv-script-lab/actions/runs/44396510649/job/135127731821) · [Reproduction workflow](https://github.com/linzhm/bsv-script-lab/blob/f278c5c64d6de94a3dd3300c858f4747576d31c7/.github/workflows/scrypt-compare.yml)

