# 4thGraph 项目

[English](README.md) · [4thGraph](../README.zh-CN.md) · [文档](../docs/README.zh-CN.md)

## 合约与证明

| 项目 | 构建与验证 |
| --- | --- |
| [PELS 计数器](pels-counter/README.zh-CN.md) | 编译状态转换并复放逐笔递增的合约 |
| [交易工作流](workflow-examples/README.zh-CN.md) | 比较并行、汇合和串行的交易计划，包含 Gforth 示例 |
| [证明计数器](proof-counter/README.zh-CN.md) | 用 Script、Circom 或证明后端构建同一个公开状态转换 |

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

## 项目工作区

从仓库根目录执行 `bash tools/setup-workspaces.sh`，在每个项目的 `workspace/` 下创建 Git 忽略的构建、缓存和日志目录。项目首页链接协议和接入指南，参考实现、构建入口和测试脚本放在对应项目。 [安装 4thGraph](../docs/install.md) · [共享钱包 SDK](../sdk/README.zh-CN.md) · [项目成果](../showcase/README.md)

## 项目 README 模板

用共享模板生成中英文介绍。工具创建缺失的 README，保留已有文件，并从当前版本清单带入构建和验证命令，链接已有的项目文档与实测数据。

```sh
python3 tools/project_readme.py my-project --title "My project" --title-zh "我的项目"
```

按提示补齐算法、入口、复现命令和实测结果，并按项目特点调整测量章节。运行 `python3 tools/project_readme.py my-project --check` 检查两份文件及模板提示是否已处理。[中文模板](../tools/templates/project-readme/README.zh-CN.md.in) · [英文模板](../tools/templates/project-readme/README.md.in) · [已填写的 Schnorr 示例](p2pkh-schnorr/README.zh-CN.md)

## 版本数据

每个项目用 `versions/index.json` 按顺序列出版本。`current` 指向当前版本，已有下一轮数据时用 `next` 指向它。SDK 有版本选择参数的项目用 `sdk_default` 记录钱包默认模板。

每个 `versions/vX.Y.Z/manifest.json` 记录上一版、编译产物、公开测试夹具、实测记录、接入指南，以及从仓库根目录执行的构建与验证命令。产物、夹具和报告使用相对于版本目录的路径。接入指南和可选的 `shared_data` 使用相对于项目的路径，后者指向沿用的旧版数据。依赖另一个项目时，用 `requires` 固定对方版本。

下一轮以当前版为基线，用同一夹具验证。将选定的锁、对应重建程序、该轮夹具和复放结果放入新的版本目录，选版后更新索引和首页。原本没有版本号的项目从仓库已有基线开始编号。运行 `PYTHONPATH=src:. python -m unittest discover -s tests -p test_layout.py` 检查版本索引和链接。 [P2PKH-R1 版本索引](p2pkh-r1/versions/index.json) · [v0.7.0 构建与复放](p2pkh-r1/versions/v0.7.0/manifest.json)
