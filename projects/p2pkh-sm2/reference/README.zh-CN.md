# P2PKH-SM2 参考实现指南

[English](README.md) · [项目概览](../README.zh-CN.md)

## 运行测试

以下命令均在 `projects/p2pkh-sm2/reference` 目录执行。本地测试需要 Python 3.12
或以上版本，以及支持 SM2 和 SM3 的 OpenSSL。

```sh
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
```

这组测试用宿主环境的 SM3 实现核对填充边界和固定前缀的中间状态，复现已发布的 SM2
标准向量，并验证一笔使用 OpenSSL 生成的密钥签署的付款。本地 Script 求值器用于检查
生成的操作码。完整输入测试还使用独立的验证引擎。

在装有 Rust 和 Cargo 的 Linux x86-64 环境中，安装[参考实现依赖](requirements.txt)，
再用固定版本的 chain-gang 扩展和 BSV Node 1.2.3 验证完整输入。差分测试核对
已安装的 Git 提交与 requirements.txt 是否一致，负向用例必须给出已知的拒绝理由。

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest -v test_sighash
bash verify.sh
```

节点启动脚本用发布校验值核对下载文件，并在临时回归测试目录中启动无对等连接的节点。
测试不会广播交易。用例覆盖连续转付、输入或输出被篡改、无效公钥和签名标量、错误的
用户标识、伪造的签名预映像以及多余的解锁栈项。

## 实现组成

| 源文件 | 用途 |
| --- | --- |
| [`sm2.py`](sm2.py) | 曲线参数、ZA、签名验证，以及需要显式指定随机数的测试签名函数 |
| [`sm3_script.py`](sm3_script.py) | 将 SM3 各轮运算展开为 Script 字节码 |
| [`p2pkh-sm2.fth`](../../../src/fourthgraph/stdlib/wallet/p2pkh-sm2.fth) | 构建锁定脚本，包含曲线运算、SM2 验签和基于 PUSHTX 的交易绑定 |
| [`asm/`](asm/) | 用于字节级比对和独立曲线测试的参考汇编 |
| [`p2pkh_sm2.py`](p2pkh_sm2.py) | 钱包接口和外部签名回调 |
| [`signed_data.py`](signed_data.py) | SignedData 付款适配、结构检查和签名验证 |

测试夹具中的私钥和签名随机数都是公开的测试数据。生产私钥的签名操作应由外部签名器完成。

## v1.0.0 模板与 Chronicle 验证

收款哈希全为零时，锁定脚本长 144,925 字节，SHA-256 为
`196dfcb8244e863521447c7069297d31938fbd80a83d5976af618cf7fbcf9462`。
生成器和 Python 脚本构造接口默认使用模板编号 `1`。[布局清单](../versions/v1.0.0/layout.json)
固定了基准字节码。[付款向量](../versions/v1.0.0/spend-all.json)记录了一笔完整的 BIP143 付款。
[16 个确定性预映像](../versions/v1.0.0/sighash-modes.json)覆盖全部有配对模式和各种无配对
SINGLE 模式。

脚本执行所有 SM3 压缩轮。实现复用循环移位和取模所需的二次幂常量，用较短的指令访问
栈顶附近的操作数，并简化后 48 轮的布尔运算。完整输入测试覆盖 BIP143 和 Chronicle
OTDA，包括混用签名模式的输入、全 SM2 的两进两出付款、由正确测试私钥签署的畸形
预映像，以及跨越 Chronicle 激活边界的花费。激活测试两侧都使用交易版本 1，以便只
检验激活标志带来的差异。

[标准向量](../versions/v1.0.0/sm2-standard.json) · [BSV Node 源码](https://github.com/bitcoin-sv/bitcoin-sv/tree/6504a3aff65ba97c0f6c80962b033e35ecbfed4b)
· [chain-gang 源码](https://github.com/linzhm/chain-gang/tree/8b60b71a12a69fdcb465d3e627dbf6f43d6ed081)

<a name="otda-constructor"></a>

## 复现 OTDA 构造器

钱包加载固定构造器，并按布局清单核对字节数和 SHA-256。离线生成器先使用 SM3 的具名片段和点运算块。为模板 `2` 生成构造器时，它评估复制片段的缓存收益，尝试按使用频率排列缓存，并选择序列化后最短的编码。在仓库根目录生成并比对文件。

```sh
python projects/p2pkh-sm2/reference/generate_otda_constructor.py /tmp/sm2-otda.hex
cmp /tmp/sm2-otda.hex projects/p2pkh-sm2/versions/v1.1.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 2 /tmp/sm2-otda-v2.hex
cmp /tmp/sm2-otda-v2.hex projects/p2pkh-sm2/versions/v1.2.0/otda-constructor.hex
```

构造器测试逐字节比对预映像、公钥和签名三项栈值，并由 BSV Node 和 chain-gang 验证完整花费。[布局与指纹](../versions/v1.1.0/layout.json) · [钱包接入](../docs/sdk.zh-CN.md)

## SignedData 付款接入

外部签名器可以按 GB/T 35275-2026 返回 DER 编码的 `SignedData`。封装携带签名值、
算法标识、签名者标识和可选的原文。钱包签名回调接收 64 字节的原始签名 `r || s`，
适配器在构造解锁脚本前验证封装并提取该签名。
[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

```python
from p2pkh_sm2 import sign_input
from signed_data import signed_data_signer

signer = signed_data_signer(provider, public_key, signer_identifier=pinned_der_issuer_and_serial)
signed_tx = sign_input(tx, input_index, funding_raw, public_key, signer, sighash_type)
```

`provider(message, user_id)` 返回 DER 字节。请通过可信配置固定公钥和完整的 DER
`IssuerAndSerialNumber`。标准第 8 章表 2 和表 3 规定外层 `SignedData.version = 1`、
内层 `SignerInfo.version = 2`、颁发者与序列号标识、以及 SM2-1 签名算法。付款适配器
和通用验签入口均执行这些规则。付款适配器接受 SM3 和附录 A.1 所用的无密钥 SM3
标识。两版测试签名器均使用无密钥 SM3。上述摘要标识及签名标识的参数可省略，也可编码
为空的 DER NULL。附录 A.1 中，无密钥 SM3 和 SM2-1 的参数均为 NULL。

付款适配器使用固定的公钥和模板规定的 SM2 用户标识，验证单个签名者对已批准的
32 字节付款消息生成的直接签名。附带原文时，原文字节必须与付款消息一致。适配器还会
检查嵌入证书、证书吊销列表和未签名属性的 DER 结构，包括适用的版本和扩展规则。
证书颁发者不能为空，证书序列号须为正数且最多占 20 个 DER 内容字节，吊销列表须有
`nextUpdate`。付款授权以配置的公钥为准。使用 PKI 的应用需要另行建立证书信任。

存在 `signedAttrs` 时，签名覆盖的是属性的 DER 字节。付款模板需要验证对交易消息
的直接签名，因此适配器拒绝属性签名。验证属性签名可使用下节所述的通用入口。

Rust 测试签名器用 RustCrypto 的 `sm2` 签名，并用 `der` 编码。Python 测试签名器
用 OpenSSL 签名，并用 `asn1crypto` 编码。两者提供相同的命令行参数和 JSON 字段。
`verify.sh` 用 Cargo 构建 Rust 版，并通过 BSV Node 和 chain-gang 重放两版签名器
生成的附带内容 BIP143 付款和分离内容 Chronicle OTDA 付款。测试还用 OpenSSL 验证
签名、检查畸形封装是否被拒绝，并逐字节对照适配器与原始签名路径生成的解锁脚本。
[Python 测试签名器](interop/python-signer/README.zh-CN.md) · [Rust 测试签名器](interop/rust-signer/README.zh-CN.md)

验收夹具穷举了 270 种付款组合和 128 种可选元数据组合，重放附录 A.1 的历史样例，
并将测试映射到标准条款。[SignedData 验收记录](signed-data-acceptance.zh-CN.md)

## SignedData 通用验签

`verify_signed_data` 使用可信公钥验证版本为 `2` 的 `SignerInfo`。映射的键为
完整的 DER 颁发者与序列号标识，值为相应签名者经认证的 SM2 公钥与用户标识。

```python
from signed_data import verify_signed_data

content = verify_signed_data(envelope, {
    signer_a_id: (signer_a_public_key, signer_a_user_id),
    signer_b_id: (signer_b_public_key, signer_b_user_id),
}, detached_content=original_content)
```

封装已附带原文时，省略 `detached_content` 即可。验签至少需要一个签名者，并要求所有
列出的签名均有效。通用入口既支持直接对原文字节签名，也支持签署 DER 编码的
`signedAttrs`。对后者，还须核对唯一的 `messageDigest` 是否等于原文的 SM3 摘要。
签名者信任、证书路径和吊销策略由调用方确定。

通用验签默认要求 SM2 数据类型。其他应用类型由调用方通过 `expected_content_type`
传入可信的点分 OID。该参数检查调用方的类型策略，直接签名覆盖原文字节。需要签名
认证内容类型时，设置 `require_signed_content_type=True`，使每个签名者都必须提供
一个与 `eContentType` 一致的已签 `contentType` 属性。该属性存在时总会检查一致性。

封装的两个摘要字段接受 `1.2.156.10197.1.401` 和 `1.2.156.10197.1.401.1`，签名
算法字段接受 SM2-1 的 `1.2.156.10197.1.301.1`。这三种标识的参数可省略，也可采用
精确的 DER NULL 编码 `05 00`。`messageDigest` 使用 PKCS #9 的
`1.2.840.113549.1.9.4`，值为一个 32 字节的 DER OCTET STRING。

通用验签和格式校验要求每个签名者的摘要 OID 出现在 `digestAlgorithms` 中，并拒绝
重复 OID。参数省略和 DER NULL 视为同一个 OID。其他 DER SET OF 集合继续遵循各字段
的规则，例如通用验签会对相同的签名者记录去重。直接付款适配器保留现有的单一 SM3
标识兼容性。

按照本项目对 GB/T 35275-2026 的解释，通用验签默认使用 `signedAttrs` 原有的 DER
`[0]` 字段字节。对使用通用 SET 标签构造签名输入的 CMS 封装，须显式指定
`signed_attrs_encoding='cms-set'`。[签名属性与算法参数的验收依据](signed-data-acceptance.zh-CN.md#签名属性与算法参数)

### SignedData 资源上限

格式校验、通用验签和付款适配器使用相同的本地解析上限。每份封装最多 8 MiB、
65,536 个 DER 元素、32 层嵌套。遍历按每个 DER 编码的字节数计入
64 MiB 的共享预算，嵌入证书和吊销列表的扩展值也计入。每个属性集合和每个属性的
值集合各允许 1,024 项。通用验签接收的分离原文最多 64 MiB。超出本地资源上限会
抛出 `SignedDataLimitsExceeded`。

### 结构与 ASN.1 模式

通过 `attribute_schemas` 可为开放类型的 `AttributeValue` 指定 ASN.1 模式。映射的
键为点分十进制属性 OID，值为 `asn1crypto` 的 ASN.1 类型。校验器按类型解码，再比对
重新编码后的规范 DER。`messageDigest` 内置 OCTET STRING 检查。遇到缺少模式的
OID 时会抛出 `MissingAttributeSchema`。类型及应用层约束由所提供的模式定义。

`validate_signed_data_format(envelope, require_signer=True, attribute_schemas=...)`
检查第 8 章的封装结构、签名者数量及已实现的 X.509 扩展规则。省略
`require_signer` 可用于检查 `SignerInfos` 为空的元数据样例。结构检查支持不带原文
的分离封装，通过时正常返回。要验证签名并取得签名原文，请调用
`verify_signed_data`，提供经认证的签名者公钥以及所需的分离原文。

还可向结构检查入口传入 `extension_schemas`，为扩展 OID 指定 `asn1crypto` 类型。
校验器按模式核对扩展的规范 DER 编码。启用此模式后，遇到无法识别且缺少模式的扩展，
会抛出 `MissingExtensionSchema`。该检查适用于证书、证书吊销列表和其中的吊销条目。

## 证书与吊销列表

`validate_crl_series(crls, extension_schemas=...)` 比较同一经认证颁发者、同一
适用范围内各 DER 吊销列表的发布编号。`validate_crl_pair(complete_crl, delta_crl,
extension_schemas=...)` 检查带编号的完整列表与增量列表能否配对。调用方应先用同一
获授权签名公钥认证两份列表。列表可以来自封装或其他经过认证的来源。

`merge_crl_revocations(complete_crl, delta_crl, published_crl=...)` 生成以增量列表
编号、有效期和适用范围为准的吊销快照。传入可信的 DER `issuer_certificate`，
可以用该证书的公钥验证所有列表。调用方也可提前认证各列表。SM2 列表须显式提供
`sm2_user_id`。`verify_crl_signature(crl, issuer_certificate, sm2_user_id=...)`
可单独验证一份列表。调用方须先建立证书路径，并确认颁发者在相应范围内具有发布权限。

传入 `published_crl` 可将合并结果与 `thisUpdate` 和编号相同的完整列表比较。
快照的 `revocation_for(issuer_name, serial_number)` 接收一个
`cryptography.x509.Name` 及序列号，返回匹配的吊销条目，查不到时返回 `None`。
间接列表的条目含有多个不同的目录名时，可用
`issuer_resolver(serial_number, candidates)` 选定经认证的颁发者名称。

用 `assess_certificate_revocation(certificate, snapshots, validation_time=...)`
判断快照是否适用于目标证书的分发点，以及所覆盖的吊销原因。可用
`load_crl_snapshot(crl, issuer_certificate, ...)` 从带编号的完整列表建立快照，
也可在合并时提供 `issuer_certificate`。验证时间须包含时区。评估返回 `revoked`、
`unrevoked` 或 `undetermined`，分别表示已吊销、全部原因均被覆盖时确认未吊销、
或者现有列表的覆盖不足以确定状态。

调用方提供可用的吊销列表。传入 `trust_anchor` 和 `intermediates` 后，本地
OpenSSL 会在指定验证时间下，把目标证书和吊销列表签名者的路径验证到同一个显式信任的
DER 证书。路径验证在独立的进程环境中运行，从常用系统安装目录选择 OpenSSL。
可通过绝对路径 `openssl_path` 固定可信安装。验证使用该版本的默认 provider，
并排除调用环境中的 OpenSSL 配置和模块覆盖。`sm2_user_id` 单独控制吊销列表验签。
直接 CRL 必须使用目标证书所选颁发者的公钥。CRL 的新旧版本和冲突按颁发者名称、
公钥和适用范围判断。间接 CRL 需要符合目标证书签名保护的分发点，并由目标路径中的
证书或该路径上的证书授权的签名者签署。同一适用分发点出现同名的不同间接签名公钥时，
这些快照不计入吊销原因覆盖。

已独立验证路径的调用方可省略 `trust_anchor`，并通过 `issuer_certificate`
固定经认证的目标证书颁发者。两者均省略时，直接 CRL 的签名公钥须能通过当前密码库
验证目标证书的签名。使用外部路径验证时，调用方负责认证间接 CRL 签名公钥。

在显式配置信任锚时，还可设置 `require_chain_revocation=True`，要求路径中选定的
中间证书和吊销列表签名证书都有新鲜、完整的吊销状态证据。每份证书所用的快照须由其
已验证的直接上级证书签发。评估会拒绝有歧义的路径、覆盖不足的证据以及已吊销的中间
证书或签名证书。[验收范围及证据](signed-data-acceptance.zh-CN.md#吊销签名适用范围与证书路径)
