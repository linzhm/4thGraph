# 4thGraph 项目

[English](README.md) · [4thGraph](../README.zh-CN.md) · [文档](../docs/README.zh-CN.md)

## 合约与证明

| 项目 | 构建与验证 |
| --- | --- |
| [PELS 计数器](pels-counter/README.zh-CN.md) | 编译状态转换并复放逐笔递增的合约 |
| [交易工作流](workflow-examples/README.zh-CN.md) | 比较并行、汇合和串行的交易计划，包含 Gforth 示例 |
| [证明计数器](proof-counter/README.zh-CN.md) | 用 Script、Circom 或证明后端构建同一个公开状态转换 |
| [BLS12-381 Groth16](groth16-bls12-381/README.zh-CN.md) | 编译模块化 Forth 验证器并回放入金花费 |
| [BN254 Groth16](groth16-bn254/README.zh-CN.md) | 构建固定声明的 Forth 验证器并在 Chronicle 回放 |
| [Winterfell BLAKE3 STARK](stark-counter/README.zh-CN.md) | 使用参考哈希配置为公开计数器出证并复放 |
| [Winterfell SHA-256 STARK](stark-winterfell-sha256/README.zh-CN.md) | 构建 SHA-256 配置并对照 BSV 轨迹开封锁 |

## 付款与签名方案

| 项目 | 构建与验证 | 钱包接入 |
| --- | --- | --- |
| [原生 P2PK 与 P2PKH](p2pk-p2pkh-baseline/README.zh-CN.md) | 构建付款锁并复放基准交易 | [secp256k1](p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1](p2pkh-r1/README.zh-CN.md) | 对照 P-256 参考锁与 Forth 编译版 | [P-256 设备签名器](p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1-Deferred](p2pkh-r1-deferred/README.zh-CN.md) | 在入金之后启用 P-256 锁 | [启用与付款](p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-Schnorr](p2pkh-schnorr/README.zh-CN.md) | 构建并测试 BIP340 锁 | [BIP340 与 MuSig2](p2pkh-schnorr/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-SM2](p2pkh-sm2/README.zh-CN.md) | 验证 SM2 签名和 SignedData | [SM2 签名器](p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| [Lamport OTS](lamport-ots/README.zh-CN.md) | 比较完整公钥锁和公钥承诺锁 | [一次性签名器](lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| [WOTS+](wots-plus/README.zh-CN.md) | 对照 Winternitz 见证与锁定模板 | [一次性签名器](wots-plus/docs/sdk.zh-CN.md#quickstart) |
| [纯模式 ML-DSA-44](ml-dsa/README.zh-CN.md) | 复放纯模式 ML-DSA-44 花费 | [FIPS 204 签名器](ml-dsa/docs/sdk.zh-CN.md#quickstart) |

## 交易测试

交易测试入口构造并验证付款及工作流的完整交易。付款例子覆盖入金、周转和退出，Deferred R1 另含带赞助输入的激活。PELS 计数器连续递增两次，串行工作流分别走 BIP143 ALL 与 OTDA ALL，证明计数器走直接 Script 后端。两个 Groth16 项目各自提供入金回放。[交易测试入口](../tests/project_transactions.py) · [BLS12-381 回放](groth16-bls12-381/docs/verification.zh-CN.md) · [BN254 回放](groth16-bn254/docs/verification.zh-CN.md)

在仓库根目录运行。Python 环境需装有 chain-gang、`ecdsa`、`coincurve` 和 `cryptography`。ML-DSA 测试签名器需要 OpenSSL 3.5 或以上。命令末尾可加项目目录名，只执行该项目。

```sh
PYTHONPATH=src:. python tests/project_transactions.py
bash tools/verify_node.sh -- python tests/project_transactions.py
```

第一条命令使用 chain-gang，第二条还会向 BSV Node 提供明确的上一输出并逐输入验证。每笔成功交易都会保留原见证、改动锁定时间并验证拒绝。两个计数器项目还会对错误后继或终端输出重新构造见证并验证拒绝。输出包含交易 ID 和序列化大小。入金出块复放、更多签名模式和证明后端见各项目指南。

## 项目工作区

从仓库根目录执行 `bash tools/setup-workspaces.sh`，在每个项目的 `workspace/` 下创建 Git 忽略的构建、缓存和日志目录。项目首页链接协议和接入指南，参考实现、构建入口和测试脚本放在对应项目。 [安装 4thGraph](../docs/install.md) · [共享钱包 SDK](../sdk/README.zh-CN.md) · [项目成果](../showcase/README.md)

## 项目 README 模板

用 Copier 创建新项目。每个可运行项目都从自己的 `projects/<name>/manifest.yaml` 生成中英文 README。[安装与创建命令](template/README.zh-CN.md)

| 字段 | 内容 |
| --- | --- |
| `schema_version` | 格式版本，当前为 `1`。 |
| `title`、`summary` | `en` 和 `zh-CN` 各一行。 |
| `entry_points` | 共用的入口名称及中英文说明。 |
| `sections` | 按固定键组织的中英文 Markdown 内容块。保留 `algorithm` 和 `reproduction`，其余按项目需要填写。 |
| `setup` | 可选的双语准备步骤，放在构建和验证命令之前。 |

段落、表格和代码块可分别用 YAML 块标量填写，相对链接从项目目录解析。生成器从 `versions/index.json` 读取当前版本，从该版本清单取得构建和验证命令，并链接已有的协议、SDK 和实测文件。用 `python3 tools/project_readme.py --all --write` 重生成全部 README，再用 `python3 tools/project_readme.py --all --check` 核对。[JSON Schema](template/manifest.schema.json) · [起始清单](template/manifest.example.yaml) · [Schnorr 清单](p2pkh-schnorr/manifest.yaml) · [生成的 README](p2pkh-schnorr/README.zh-CN.md)

## 版本数据

每个项目用 `versions/index.json` 按顺序列出版本。`current` 指向当前版本，已有下一轮数据时用 `next` 指向它。SDK 有版本选择参数的项目用 `sdk_default` 记录钱包默认模板。

每个 `versions/vX.Y.Z/manifest.json` 记录上一版、编译产物、公开测试夹具、实测记录、接入指南，以及从仓库根目录执行的构建与验证命令。产物、夹具和报告使用相对于版本目录的路径。接入指南和可选的 `shared_data` 使用相对于项目的路径，后者指向沿用的旧版数据。依赖另一个项目时，用 `requires` 固定对方版本。

下一轮以当前版为基线，用同一夹具验证。将选定的锁、对应重建程序、该轮夹具和复放结果放入新的版本目录，选版后更新索引和首页。原本没有版本号的项目从仓库已有基线开始编号。运行 `PYTHONPATH=src:. python -m unittest discover -s tests -p test_layout.py` 检查版本索引和链接。 [P2PKH-R1 版本索引](p2pkh-r1/versions/index.json) · [v0.7.0 构建与复放](p2pkh-r1/versions/v0.7.0/manifest.json)
