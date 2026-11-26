# P2PKH-Schnorr v0.1.0

[English](README.md) · [BSV Script Lab](../../README.zh-CN.md)

**实验付款模板。** 在 BSV 上向 BIP340 x-only 公钥的哈希付款。钱包只需在固定锁定脚本中填入 20 字节的所有者哈希，外部签名器返回标准 64 字节 BIP340 签名。

两方可以通过 BIP327 MuSig2 共同出款。现有锁接收聚合公钥的横坐标和最终的 BIP340 签名，沿用现有钱包接口。参考夹具覆盖签名中断，并与要求双方都签字的原生 `CHECKMULTISIG` 实测对照。[MuSig2 与原生 2-of-2](docs/threshold-comparison.zh-CN.md)

**[钱包 SDK 接入](docs/sdk.zh-CN.md#quickstart)** · [付款协议](docs/spec.zh-CN.md) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## 复现验收

从仓库根目录创建 Python 3.12 项目环境。测试使用公开夹具密钥和固定版本的 chain-gang。BSV Node 复放在隔离的 regtest 上进行。

```sh
python3.12 -m venv .venv/p2pkh-schnorr
.venv/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
export SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/p2pkh-schnorr/bin/python"
PYTHONPATH=. "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH="$PWD:$PWD/projects/p2pkh-schnorr/reference" \
  bash shared/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_schnorr test_musig2
bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-schnorr
```

验收夹具在 libsecp256k1 和两套脚本引擎上核对全部 19 条 BIP340 官方验签向量，包括空消息与变长消息，并用公开测试密钥和辅助随机数复算了 8 条官方签名向量。付款矩阵覆盖交易版本 1 和 2，以及有同索引输出的全部 12 种 ForkID 和 Chronicle OTDA 组合。测试核对锁定时间变化后的拒绝结果，以及 ALL、NONE、SINGLE 对输出变化的各自约束。其他用例覆盖错误坐标、所有者校验、手续费平衡和 Chronicle 未激活的情况。

## 交易实测

固定锁为 **126,018 字节**，所有者槽位从字节偏移 **238** 开始。以下两进两出场景都新建两个 Schnorr 输出。解锁脚本包含签名预映像、BIP340 签名和坐标见证。

| 签名模式 | 每个锁定脚本 | 每个解锁脚本 | 整笔交易 | 新增输入 | 新增输出 | 入金与退出 | 一次周转 | 两栈载荷峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | 126,018 | 329 | 252,816 | 372 | 126,031 | 253,041 | 505,858 | 3,341 |
| Chronicle OTDA ALL | 126,018 | 252,333 | 756,828 | 252,501 | 378,093 | 253,056 | 1,009,883 | 504,494 |

单位均为字节。栈载荷取开发求值器测得的第一个输入的主栈和备用栈合计峰值。完整输入在 BSV Node 1.2.3 和 chain-gang 上用显式提供的上一输出验证。OTDA ALL 的每份预映像都包含完整输出字节。[模板布局及指纹](template/layout.json) · [基准口径](../../shared/benchmark.zh-CN.md)

```sh
bash shared/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m shared.benchmark \
  --project p2pkh-schnorr --venvs-dir .venv --output /tmp/p2pkh-schnorr-benchmark
```

在 BSV Node 1.2.3 的默认 regtest 策略下，ForkID ALL 和 OTDA ALL 两组带 UTXO 的入金与退出交易均进入内存池并出块。

```sh
bash shared/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m shared.benchmark_admission \
  p2pkh-schnorr --output /tmp/p2pkh-schnorr-admission.json
```

[sCrypt 对照](docs/scrypt-comparison.zh-CN.md)包括 2021 年文章链接的验签器，以及用 sCrypt 编写的同算法、同见证布局的 BIP340 实现。[原生 2-of-2 对照](docs/threshold-comparison.zh-CN.md)包含完整交易生命周期和链下签名材料的实测数据。
