<h1 align="center">BSV Script Lab</h1>

<p align="center"><strong>在 Bitcoin Script 中验证签名与交易授权</strong></p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="#project-index">实验项目</a> ·
  <a href="#sighash-modes">签名模式</a> ·
  <a href="#run-checks">复现验证</a>
</p>

在 BSV 上生成锁定脚本、用公开向量重放已签名的交易，并对照每种签名实际覆盖的交易字段。

---

<a name="project-index"></a>

## 实验项目

| 项目 | 版本 | 研究内容 | 开发入口 |
|---|---|---|---|
| [P2PKH-R1](projects/p2pkh-r1/README.md) | v0.1 | 以 P-256 公钥哈希收款，普通付款由设备签名一次 | [协议规范](projects/p2pkh-r1/docs/spec.zh-CN.md) · [TypeScript、Rust 和 Go 接入](projects/p2pkh-r1/docs/sdk.zh-CN.md) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.md) | v0.1 | 1,435 字节的入金锁承诺后续启用的 R1 输出 | [锁定格式与复现验证](projects/p2pkh-r1-deferred/README.md) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.zh-CN.md) | v1.0.0 | 用 Bitcoin Script 执行 SM2 验签，并计算 SM3 与 ZA | [协议规范](projects/p2pkh-sm2/docs/spec.zh-CN.md) · [Python 参考实现](projects/p2pkh-sm2/reference/README.zh-CN.md) |
| [Lamport OTS](projects/lamport-ots/README.md) | v0.1 | 基于 SHA-256 的一次性授权。每组密钥对应一个 UTXO，只签一次。 | [安全分析](projects/lamport-ots/docs/security.md) · [验证记录](projects/lamport-ots/docs/validation.md) |
| [WOTS+](projects/wots-plus/README.md) | v0.1 | 基于 SHA-256 哈希链的一次性授权，签名原始长度为 2,144 字节 | [协议规范](projects/wots-plus/docs/spec.md) · [复现验证](projects/wots-plus/README.md#run-the-checks) |
| [ML-DSA-44](projects/ml-dsa/README.md) | v0.1 | FIPS 204 纯模式消息验签，以及交易绑定的付款模板 | [实现与测量](projects/ml-dsa/README.md) |
| [原生 P2PK 和 P2PKH](projects/p2pk-p2pkh-baseline/README.md) | v0.1 | 原生签名锁及完整输入的验收基准 | [验收矩阵](projects/p2pk-p2pkh-baseline/reference/acceptance.md) |

v0.1 表示开发基线。各项目文档记录可选模板及其验收范围。

<details>
<summary><strong>对照脚本尺寸</strong></summary>

下表为参考模板使用常规 ForkID `ALL`（`0x41`）时的脚本字节数。

| 模板 | 锁定脚本 | 解锁脚本 |
|---|---:|---:|
| [P2PKH-R1](projects/p2pkh-r1/template/layout.json) | 59,582 字节 | 326 字节 |
| [P2PKH-SM2 v1.0.0](projects/p2pkh-sm2/template/layout.json) | 144,925 字节 | 291 字节 |
| [Lamport OTS](projects/lamport-ots/template/measurement.json) | 22,780 字节 | 8,357 字节 |
| [WOTS+](projects/wots-plus/docs/validation.md) | 42,266 字节 | 2,310 字节 |
| [ML-DSA-44](projects/ml-dsa/README.md#script-sizes) | 926,403 字节 | 2,588 字节 |

Lamport 的锁定脚本包含公钥。普通 OTDA 路径的解锁脚本随参与签名的交易数据变化。

</details>

<a name="sighash-modes"></a>

## 交易签名模式

五个支付模板的参考实现均支持下列十二种 BIP143 ForkID 与 Chronicle OTDA 组合。每个输入独立选择模式，普通付款默认使用 `0x41`。P2PKH-R1-Deferred 启用默认使用 `0x43`，每种模式都要求同索引输出存在。

| 输出覆盖范围 | BIP143 ForkID | ForkID 加 ANYONECANPAY | Chronicle OTDA | OTDA 加 ANYONECANPAY |
|---|---|---|---|---|
| `ALL` · 全部输出 | `0x41` | `0xc1` | `0x61` | `0xe1` |
| `NONE` · 输出可变 | `0x42` | `0xc2` | `0x62` | `0xe2` |
| `SINGLE` · 同索引输出（如存在） | `0x43` | `0xc3` | `0x63` | `0xe3` |

<details>
<summary><strong>P2PKH-SM2 v1.0.0 与无配对输出的 SINGLE</strong></summary>

同一笔交易可在不同输入上混用 ForkID 与 OTDA。OTDA `SINGLE` 缺少同索引输出时，脚本通过补充预映像把 SM2 授权绑定到当前输入。

[SM2 交易绑定规则](projects/p2pkh-sm2/docs/spec.zh-CN.md#当前输入交易绑定) · [16 个签名向量](projects/p2pkh-sm2/template/sighash-modes.json)

</details>

<a name="run-checks"></a>

## 复现验证

在仓库根目录核对文档链接，并重新生成 R1 的基准脚本字节。

```sh
python3 -m unittest shared.test_layout -v
```

<details>
<summary><strong>P2PKH-R1 · 生成锁定脚本并验证完整输入</strong></summary>

在 Linux x86-64 环境使用 Python 3.12、Git 和 Rust。生成锁定脚本前，将 `R1_OWNER_HASH160` 设为收款人 20 字节公钥哈希的十六进制值。随附的 R1 测试密钥是公开的，对应输出仅用于本地测试。

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?请设置收款公钥哈希}"
bash verify.sh
```

[参考实现与一致性测试](projects/p2pkh-r1/reference/README.md)

</details>

<details>
<summary><strong>P2PKH-SM2 · 标准向量与 OpenSSL 互操作验证</strong></summary>

使用 Python 3.12 或以上版本，以及支持 SM2 和 SM3 的 OpenSSL。

```sh
cd projects/p2pkh-sm2/reference
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
```

[完整输入测试、Chronicle 激活用例与验证范围](projects/p2pkh-sm2/reference/README.zh-CN.md)

</details>

<details>
<summary><strong>Lamport OTS · 复现向量和节点检查</strong></summary>

激活 Python 环境后，在仓库根目录运行。

```sh
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
```

Linux x86-64 用 `bash projects/lamport-ots/reference/verify.sh`，Apple Container 用 `bash projects/lamport-ots/reference/verify_apple.sh`。

[参考工具和实测数据](projects/lamport-ots/reference/README.md)

</details>

节点环境与验证范围见各项目的参考文档。GitHub Actions 采用手动触发。[运行记录](https://github.com/linzhm/bsv-script-lab/actions)

## 仓库结构

每个项目在 `projects/<name>/` 下维护规范、参考实现和测试向量。P2PKH-R1 还提供 TypeScript、Rust 和 Go SDK。共用的脚本编码、交易序列化和节点验证启动器见 [`shared/`](shared/README.md)。

## 跨项目交易基准

对照七个项目的完整签名交易、输入输出边际成本和付款生命周期。
[运行基准与验收](shared/benchmark.zh-CN.md)
