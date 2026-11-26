# 4thGraph 标准库

用 Forth 2012 的 `REQUIRE filename` 加载源码。标准库清单中的 `std/…` 名称用于接口目录和构建报告。

| 模块 | 公开接口 | 现有项目 |
| --- | --- | --- |
| `std/u32` | `u32-inc ( u32 -- u32 )`，按 32 位回绕 | [PELS Counter](../../projects/pels-counter/pels-counter.fth) |
| `std/p2pk` | `p2pk-lock ( bytes -- bytes )`，接收 33 字节压缩公钥并返回锁脚本 | [库源码](../../src/fourthgraph/stdlib/p2pk.fth) · [P2PK 示例](../../projects/p2pk-p2pkh-baseline/forth/p2pk.fth) |
| `std/p2pkh` | `p2pkh-lock ( bytes -- bytes )`，接收 20 字节公钥哈希并返回锁脚本 | [库源码](../../src/fourthgraph/stdlib/p2pkh.fth) · [P2PKH 示例](../../projects/p2pk-p2pkh-baseline/forth/p2pkh.fth) |
| `std/p256` | `p256-add`、`p256-double`，项目式坐标，保留栈底的 `p b3` | [P-256 内核](../../src/fourthgraph/stdlib/p256.fth) |
| `std/script-fragments` | 构造栈搬运、32 字节反序和无符号大端整数解码片段 | [库源码](../../src/fourthgraph/stdlib/script-fragments.fth) |
| `std/secp256k1` | 齐次射影点加、仿射混合点加、倍点和标量分解 | [曲线内核](../../src/fourthgraph/stdlib/secp256k1.fth) |
| `std/bip340` | `bip340-verify ( script -- script )`，构造 BIP340 验签片段 | [付款示例](../../projects/p2pkh-schnorr/README.zh-CN.md) |
| `std/groth16-bls12-381` | `groth16-bls12-381-verify ( -- groth16-verified )`，由 BLS12-381 verifier 后端编译 | [Groth16 Forth 源码](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) |
| `std/verify` | `relation: TRANSITION ROUTE ;`，声明一个可用多种后端验证的关系 | [状态验证示例](../../projects/proof-counter/verify-state.fth) |

支付构造词在返回脚本前检查字段宽度，P2PK 为 33 字节，P2PKH 为 20 字节。钱包接口对压缩公钥另做 secp256k1 点检查，Script 花费仍通过原生 `CHECKSIG` 验证签名。

文件在调用方的词典中加载。同一文件只加载一次，循环依赖会在构建时报错。标准库清单定义公开接口，诊断和改写记录能指向文件内行列。构建记录实际加载文件的 SHA-256 摘要，以及已登记库的接口摘要。`--capabilities` 列出公开栈签名、参数、失败语义和后端。 [语法书](syntax.md)

## 库、入口和产物

Forth 的库和应用使用同一种词定义。加载文件会解释顶层内容，执行某个词时才运行该词的主体。Forth 2012 的 `REQUIRE` 调用 `REQUIRED` 以避免重复加载。Gforth 的 `string.fs` 用 `require` 声明依赖，把相关字符串操作和各自的栈效果放在一起。4thGraph 在构建时执行 `REQUIRE`。文件名相对当前源码解析，也可以从打包的标准库中加载。 [Forth 2012 REQUIRED](https://forth-standard.org/standard/file/REQUIRED) · [Gforth 文件加载](https://gforth.org/manual/Forth-source-files.html) · [Gforth string.fs](https://github.com/forthy42/gforth/blob/master/string.fs#L21)

- **按调用边界拆模块。** P2PK 的调用者提供压缩公钥，P2PKH 的调用者提供公钥哈希。两种锁可以独立构建，所以各有模块。共享坐标约定与域运算的 `p256-add` 和 `p256-double` 属于同一模块。按相关功能组织模块，也便于把内部辅助词留在模块中。 [Rust 模块组织](https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html)
- **显式列出公开词。** 在 `stdlib.py` 登记每个导出词的栈签名、输入契约和失败行为。辅助词随文件加载。库的调用方依赖清单规定的公开接口，便于对单个词做差分和提取。 [Scheme R7RS 库声明](https://standards.scheme.org/r7rs-html5/index.html#5.6.1)
- **示例选择入口，构建产生脚本。** `stdlib/p2pk.fth` 定义 `p2pk-lock`，`projects/p2pk-p2pkh-baseline/forth/p2pk.fth` 导入该词并声明入口。加载示例时解析依赖和定义。构建时执行构造词得到序列化锁，BSV 节点在验证花费时执行生成锁中的 `OP_CHECKSIG`。 [P2PK 构建和复放](../../projects/p2pk-p2pkh-baseline/forth/README.md)

以下例子把两个项目的库词编译进同一个 Script。回绕后的计数和生成的 P2PKH 锁都保留在数据栈上。 [完整 Forth 源码](../../projects/workflow-examples/library-composition.fth)

```forth
REQUIRE stdlib/u32.fth
REQUIRE stdlib/p2pkh.fth
: advance-and-pay ( u32 bytes -- u32 bytes ) swap u32-inc swap p2pkh-lock ;
```

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol --capabilities
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol "projects/workflow-examples/library-composition.fth" \
  --entry advance-and-pay --optimize stack
```

## 验证路径

`relation:` 声明公开的 `current → next → route` 关系。每种候选检查相同的部署状态、真实输入、结算或复核输出，以及记录新状态的回执。电路后端共享 `next, route, current, bindLo, bindHi` 的公开信号顺序。证明路径从经认证的 BIP143 ALL 原像取得 SHA-256d，核对证明中的两个绑定字段。

| 路径 | 资格条件 |
| --- | --- |
| 直接 Script | 两个词都可以下沉到 Script，且调用方允许直接验证 |
| 透明 R1CS | 电路能由同一份 Forth 编译，启用固定版本的 Circom/snarkjs，且策略允许透明赋值 |
| BLS12-381 Groth16 | 外部 `.zkey` 和 Phase 2 `.ptau` 通过 snarkjs 对生成的 BLS12-381 R1CS 的验证 |

通过资格检查后，默认按部署锁加一次花费见证的序列化字段字节上界排序。也可用 `--objective lock-bytes` 只比较部署锁。BLS12-381 对三种见证布局分别报价。报告列出选择、排除原因、库摘要、R1CS 与验证密钥摘要。复放另外记录完整部署、花费字节及两引擎的判定。

`compilations` 给出直接验证锁的 Script 字节和生成的 Circom 源码，构建状态与候选资格分别记录。`--max-expanded-ops` 在进入两个后端前限制展开规模，按调用图累计重复调用及分支。`--max-lock-bytes` 在排序前排除超长的候选锁，包括证明验证锁。验证路径共用 `--spend-fee`，以相同输出金额复放。

安装版提供 `4thgraph-circuit` 和 `4thgraph-verify`。它们可在仓库外读取打包的标准库。使用 `relation:` 时，规划器生成与同一份已解析 Forth 对应的 R1CS。独立的 `proof_contract.py --verification-key` 入口用于由部署方核对的外部 R1CS。 [安装和依赖](../install.md)

当前 `relation:` 支持有界的公开状态转换。跨任意长度历史的溯源需要另外定义经过认证的前序状态或历史证明接口。只有能约束同一条历史关系和实际花费的后端，才可接替超预算的直接 Script。

`--policy allow-direct` 让所有合格路径参与排序。调用方需要外部证明时，用 `require-proof`。应用要求 Groth16 时，用 `require-groth16`。BN254 固定声明适配器有不同的授权和花费绑定接口，本例的报告会列出其排除原因。

从仓库根目录复放。用已有复放报告里的测试公钥生成 `keys.json`。Groth16 选项接收与这份电路对应且由部署方认可的外部设置。本地测试设置仅用于 regtest。

```sh
source="projects/proof-counter/verify-state.fth"
keys="workspace/workflow-test-keys.json"

PYTHONPATH=src:. python -m fourthgraph.verification.circuit_backend "$source" --output "workspace/verify-state.circom"
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python -m fourthgraph.verification.plan "$source" --keys "$keys" --current 19 \
  --target both --r1cs --replay --output "workspace/v0.2.5-relation-auto.json"
```

对同一命令加上 `--groth16 "$zkey" "$ptau"` 可让 BLS12-381 也参加选择。当前样例的默认策略选择直接 Script，使用 `--policy require-proof` 会选 R1CS。要求 Groth16 时，按总字段字节选择 `affine-inline`，按锁字节选择 `affine-witness`。

用 `--policy require-groth16 --max-lock-bytes 400000` 保留整路字节目标并施加锁预算。`affine-inline` 的锁超出该预算，编译器会改选 `affine-witness`。
