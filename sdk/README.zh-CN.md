# 4thGraph 钱包 SDK

[English](README.md) · [4thGraph](../README.zh-CN.md)

构造与识别 BSV 锁定脚本，向签名器发出签名请求，并组装已签名的交易。TypeScript、Rust、Go 和 Python 客户端共用本地 Python 桥接程序和当前检出的付款模板。

**[运行离线示例](#quickstart)** · [接入钱包](docs/integration.zh-CN.md) · [接口参考](docs/reference.zh-CN.md) · [选择签名方案](#scheme-integrations)

<a name="quickstart"></a>

## 运行离线示例

在仓库根目录用 Python 3.12 创建本地环境，用公开测试密钥签署一笔原生 P2PKH 付款。

```sh
python3.12 -m venv workspace/sdk-venv
workspace/sdk-venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements-sdk.txt ecdsa==0.19.1
PYTHONPATH=src:. workspace/sdk-venv/bin/python -m sdk.examples.receive_and_pay
```

输出应包含模板 `p2pkh`、25 字节锁定脚本和交易 ID。示例在离线环境中花费一个模拟输出。 [示例源码](examples/receive_and_pay.py)

<a name="wallet-workflow"></a><a name="从独立钱包仓库接入"></a><a name="prepared-payments"></a>

[配置语言绑定](docs/integration.zh-CN.md#bridge-setup) · [签署已组装的交易](docs/integration.zh-CN.md#prepared-payments)

<a name="scheme-integrations"></a>

## 选择签名方案

| 项目 | 签名请求 | 接入指南 |
| --- | --- | --- |
| 原生 P2PK/P2PKH | secp256k1 摘要，low-S DER | [原生 SDK](../projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-R1 | P-256 摘要或交给设备散列的消息，64 字节 `r ∥ s` | [R1 SDK](../projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-R1-Deferred | 启用操作依据承诺的 R1 输出生成解锁脚本 | [Deferred SDK](../projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-SM2 | SM2 消息和用户 ID，64 字节 `r ∥ s` 或 DER SignedData | [SM2 SDK](../projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-Schnorr | 32 字节 BSV 交易消息，64 字节 BIP340 签名 | [Schnorr SDK](../projects/p2pkh-schnorr/docs/sdk.zh-CN.md#quickstart) |
| Lamport OTS | 32 字节摘要，8,192 字节签名 | [Lamport SDK](../projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| WOTS+ | 32 字节摘要，2,144 字节签名 | [WOTS+ SDK](../projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| 纯模式 ML-DSA-44 | 32 字节消息和空上下文，2,420 字节签名 | [ML-DSA SDK](../projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

<a name="calls-and-data"></a><a name="调用与数据"></a><a name="one-time-signing"></a><a name="troubleshooting"></a><a name="复放基线"></a>

[调用与数据格式](docs/reference.zh-CN.md#calls-and-data) · [一次性签名](docs/reference.zh-CN.md#one-time-signing) · [排错](docs/reference.zh-CN.md#troubleshooting) · [复放四种语言的客户端](docs/reference.zh-CN.md#replay)
