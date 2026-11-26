# P2PKH-Schnorr v0.6.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md)

**实验付款模板。** 在 BSV 上向 BIP340 x-only 公钥的哈希付款。钱包只需在固定锁定脚本中填入 20 字节的所有者哈希，外部签名器返回标准 64 字节 BIP340 签名。

两方可以通过 BIP327 MuSig2 共同出款。现有锁接收聚合公钥的横坐标和最终的 BIP340 签名，沿用现有钱包接口。参考夹具覆盖签名中断，并与要求双方都签字的原生 `CHECKMULTISIG` 实测对照。[MuSig2 与原生 2-of-2](docs/threshold-comparison.zh-CN.md)

**[钱包 SDK 接入](docs/sdk.zh-CN.md#quickstart)** · [付款协议](docs/spec.zh-CN.md) · [复现与验证](#复现验收) · [交易成本](#交易实测) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## 从 Forth 构建

付款示例通过 `REQUIRE stdlib/bip340.fth` 引入 4thGraph 标准库。`schnorr-lock` 将库里的验签词与所有者校验、当前输入绑定组合成付款锁。`schnorr-unlock` 为每次花费构造解锁脚本。[付款示例源码](reference/schnorr.fth) · [4thGraph 验签库](../../src/fourthgraph/stdlib/bip340.fth)

在仓库根目录运行 `PYTHONPATH=src:. python projects/p2pkh-schnorr/reference/generate_template.py --check` 核对锁和布局。用 `--write` 重新生成。早期版本的模板可在 Git 历史中查阅。

钱包 SDK 用编译产物识别输出和构造收款锁。验证外部签名后，SDK 将审批过的预映像和公开见证交给 `schnorr-unlock`，再把脚本写入对应输入。[钱包 SDK](docs/sdk.zh-CN.md#quickstart)

验签器把签名标量拆成两段，用 secp256k1 自同态分解挑战标量，再用 64 个两位窗口联合累加四个 128 位分量。固定基点表使用仿射坐标和专用点加。独立验签器编译后为 29,415 字节。[标量分解和窗口构造](docs/spec.zh-CN.md#联合标量乘法)

## 复现验收

从仓库根目录创建 Python 3.12 项目环境。测试使用公开夹具密钥和固定版本的 chain-gang。BSV Node 复放在隔离的 regtest 上进行。

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-schnorr/workspace/p2pkh-schnorr
projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
export SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python"
PYTHONPATH=src:. "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH="$PWD:$PWD/projects/p2pkh-schnorr/reference" \
  bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_schnorr test_musig2
bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

验收在 libsecp256k1 和两套脚本引擎上核对全部 19 条 BIP340 官方验签向量，包括空消息与变长消息，并用公开测试密钥和辅助随机数复算了 8 条官方签名向量。付款矩阵覆盖交易版本 1 和 2，以及有同索引输出的全部 12 种 BIP143 和 Chronicle OTDA 组合。测试核对锁定时间变化后的拒绝结果，以及 ALL、NONE、SINGLE 对输出变化的各自约束。其他用例覆盖错误坐标、所有者校验、手续费平衡、Chronicle 未激活，以及两张表的全部索引、标量分解和无穷远点结果。

## 交易实测

固定锁为 **30,398 字节**，所有者槽位从字节偏移 **238** 开始。以下两进两出场景都新建两个 Schnorr 输出。解锁脚本包含签名预映像、BIP340 签名和坐标见证。

| 签名模式 | 每个锁定脚本 | 每个解锁脚本 | 整笔交易 | 新增输入 | 新增输出 | 入金与退出 | 一次周转 | 两栈载荷峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL | 30,398 | 329 | 61,572 | 372 | 30,409 | 61,798 | 123,369 | 3,325 |
| Chronicle OTDA ALL | 30,398 | 61,087 | 183,088 | 61,253 | 91,235 | 61,811 | 244,899 | 122,006 |

单位均为字节。栈载荷取开发求值器测得的第一个输入的主栈和备用栈合计峰值。完整输入在 BSV Node 1.2.3 和 chain-gang 上用显式提供的上一输出验证。OTDA ALL 的每份预映像都包含完整输出字节。[模板布局及指纹](template/layout.json) · [基准口径](../../docs/benchmark.zh-CN.md)

```sh
bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir projects/p2pkh-schnorr/workspace --output projects/p2pkh-schnorr/workspace/build/benchmark
```

在 BSV Node 1.2.3 的默认 regtest 策略下，BIP143 ALL 和 OTDA ALL 两组带 UTXO 的入金与退出交易均进入内存池并出块。

```sh
bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --output projects/p2pkh-schnorr/workspace/build/admission.json
```

[sCrypt 对照](docs/scrypt-comparison.zh-CN.md)包括 2021 年文章链接的验签器，以及用 sCrypt 编写的同见证布局 BIP340 实现。[原生 2-of-2 对照](docs/threshold-comparison.zh-CN.md)包含完整交易生命周期和链下签名材料的实测数据。
