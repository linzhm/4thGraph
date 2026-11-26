# 钱包 SDK 接口参考

[English](reference.md) · [SDK 首页](../README.zh-CN.md) · [接入指南](integration.zh-CN.md)

[调用与数据](#calls-and-data) · [一次性签名](#one-time-signing) · [排错](#troubleshooting) · [复放基线](#replay)

<a name="calls-and-data"></a>

## 调用与数据

| TypeScript | Rust / Python | Go | 返回值 |
| --- | --- | --- | --- |
| `createLock` | `create_lock` | `CreateLock` | 根据公钥或受支持的 20 字节所有者哈希生成原始锁定脚本 |
| `recognize` | `recognize` | `Recognize` | 匹配的项目、模板，以及可提取的所有者或承诺信息 |
| `prevoutFromFunding` | `prevout_from_funding` | `PrevoutFromFunding` | 显示顺序的 `txid`、父交易输出索引 `vout`、聪金额 `valueSats` 和原始 `script` |
| `signPayment` | `sign_payment` | `SignPayment` | 使用已审批输出的版本 2 单输入交易，sequence 为最终值，locktime 为零 |
| `signInput` | `sign_input` | `SignInput` | 在指定 `inputIndex` 写入解锁脚本后的整笔交易 |
| `activate` | `activate` | `Activate` | 在指定 `inputIndex` 写入 Deferred 启用解锁脚本后的整笔交易 |

TypeScript、Rust、Go 用偶数长度、无前缀的十六进制传递交易、公钥和脚本，用规范的十进制字符串表示整聪。Python 用字节和整聪数值，txid 仍为显示顺序字符串。四种语言的签名回调都接收和返回二进制。识别未命中返回 `null`、`None` 或 `nil`。请求格式无效时返回错误。

钱包可以直接传入已核验的 prevout。`prevoutFromFunding` 解析入金交易并计算 txid，钱包仍需通过可信链视图核对输出存在、确认、金额和可花费状态。`signPayment` 检查输出金额加手续费是否等于输入金额。多输入交易由钱包核对所有上一输出和总手续费，再用 `signInput` 逐个填写尚未签名的输入。`prevout.vout` 始终对应父交易，`inputIndex` 始终对应本次花费交易。

普通付款默认使用 BIP143 ALL（`0x41`）。`SINGLE` 需要同索引输出，选择 OTDA 时从可信链视图填写 `chronicleActive`。签名请求包含 `algorithm`、`payloadKind`（`digest` 或 `message`）、`signatureFormat`、`sighash`、`payload`，SM2 还提供 `userId`。各项目的签名方式和编码见下表。

省略重建选项即可使用所选方案的默认行为。SM2 在能缩短 OTDA 解锁脚本时自动重建。Go 的 `CompressOTDA` 为 `*bool`，用 `nil` 选择默认行为。Rust 的 `compress_otda` 为 `Option<bool>`，用 `None` 选择默认行为。要复现 SM2 的原样编码，Go 传入指向 `false` 的指针，Rust 传入 `Some(false)`，TypeScript 和 Python 传入 `false`。

<a name="one-time-signing"></a>

## 一次性签名

Python 接入 Lamport 或 WOTS+ 时，用 `sign_once = durable_signer(database, project, spend_key, sign_digest)` 封装摘要签名器，再传入回调 `lambda request: sign_once(request.payload)`。各钱包进程和各模板格式共用同一个数据库和规范化的公钥。[一次性签名器](../../src/fourthgraph/bsv/one_time_signer.py)

<a name="troubleshooting"></a>

## 排错与重试

| 现象 | 检查项 |
| --- | --- |
| 桥接进程启动失败 | 核对解释器和桥接脚本的绝对路径、检出的模板，以及依赖安装到了哪个解释器。用同一解释器运行离线示例。 |
| 识别未命中或准备签名失败 | 核对项目与实际上一输出的字节。已组装的交易应检查 `inputIndex`、`prevout.vout`、空解锁脚本和所选 sighash。使用 `signPayment` 时，核对输出金额加手续费是否等于输入金额。 |
| 签名器已返回，组装却失败 | 核对回调返回的是请求指定的原始字节或 DER，并核对签的是摘要还是消息。保留签名器状态，尤其要保留可能已释放签名的一次性密钥记录。 |
| 广播未被接收 | 核对入金输出是否仍可花费，并检查广播端返回的策略错误。可重播时用已保存的原始字节。使用一次性密钥时，构造替代交易前先核对已有签名状态。 |

<a name="replay"></a>

## 复放基线

完成[离线示例](../README.zh-CN.md#quickstart)后，用 Node.js 24+、Go 1.23+ 和 Cargo 复放四种语言绑定。编译固定版本的 chain-gang 还需要 Rust 和 C 编译工具链。以下命令在 Linux x86-64 的仓库根目录运行。

```sh
workspace/sdk-venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/workspace/sdk-venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

复放比较四种语言生成的锁定脚本、签名请求和已签交易字节，再由 chain-gang 和 BSV Node 使用显式上一输出验证公开向量。实际入资的 regtest 还会测量指定策略下的内存池接收和出块。集成依赖转发或出块时，应执行这一步。[基准与入资 regtest 指南](../../docs/benchmark.zh-CN.md)
