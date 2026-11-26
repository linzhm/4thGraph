# P2PKH-R1-Deferred v0.2.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

生成入金短锁，在同一索引安排它承诺的 R1 目标输出，再调用 `activate`。启用后的输出按普通 R1 流程花费。

[协议规范](docs/spec.zh-CN.md) · [安全分析](docs/developer.zh-CN.md#security) · [复现与验证](#开发与复现) · [交易成本](#实测交易成本)

Deferred 将生成完整 R1 锁定脚本的成本推迟到启用阶段。[1,435 字节的入金短锁](template/v0.2.0/template.hex)承诺一个等额的 [46,302 字节 P2PKH-R1 v0.2.0 目标输出](../p2pkh-r1/template/v0.2.0/template.hex)。已有短锁继续采用其原先承诺的目标版本。

## 使用场景与取舍

如果需要批量创建体积较小的入金输出，而且可以在后续出款前集中启用，可以评估 Deferred。每个短锁承诺目标 R1 的所有者、模板和全额金额。任何持有所需数据并能提供手续费的参与方都可构造启用交易。之后花费普通 R1 输出时，仍需所有者签名。

需预算额外一笔交易及手续费来源。每个启用输入与所承诺的 R1 输出同索引时，可以批量启用。确认前，钱包继续跟踪短锁 UTXO。暂时找不到手续费赞助输入时，资金留在短锁里。若用户需要到账即花费，或主要目标是降低总手续费，应和普通 R1 对比从入金到退出的完整成本。[启用成本](#实测交易成本)

## 启用与后续付款

1. 使用 `funding_output` 或 `funding_output_from_owner_hash` 生成入金输出。接收时核对短锁、金额和两项目标承诺。Python 的 `recognize` 返回 `target_r1_version`。统一客户端通过 `targetTemplate` 返回承诺的版本。
2. 将启用输入和目标输出放在同一索引，再调用 `activate_input`。手续费赞助方需要签自己的输入。BIP143 SINGLE 直接分支的解锁为 160 字节。双检查分支另带所选模式的摘要，解锁为 197 字节。全部 12 种启用签名类型都要求同索引输出存在。
3. 启用完成后，使用普通 R1 钱包和签名器花费该输出。符合条件的后续付款可以使用 Chronicle OTDA 重建。

启用解锁已经通过 BIP143 SINGLE 携带目标输出的承诺，双检查分支另带一个摘要。完整 R1 目标锁占用启用交易的实际输出。

## 开发与复现

详见[协议规范](docs/spec.zh-CN.md)、[钱包 SDK](docs/sdk.zh-CN.md)、[模板布局](template/v0.2.0/layout.json)、[启用向量](template/v0.2.0/activation-single.json)、[十二种模式向量](template/v0.2.0/sighash-modes.json)和[验收矩阵](reference/acceptance.md)。

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
PYTHONPATH=src:. python projects/p2pkh-r1-deferred/reference/generate_vectors.py
bash projects/p2pkh-r1-deferred/reference/verify.sh
```

## 实测交易成本

基准用两个短锁输入和一个手续费赞助输入，产生两个 R1 v0.2.0 输出。新增一对启用时，同时增加输入与同索引目标。只增输出时，由赞助输入额外支付。表中单位均为序列化字节。

| 启用模式 | 3 进 2 出 | 新增一对启用 | 新增输出 | 入金、启用和退出 | 含一次周转 |
| --- | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL | 93,259 | 46,552 | 46,313 | 97,125 | 190,498 |
| OTDA ALL | 93,260 | 46,551 | 46,312 | 97,139 | 198,389 |

两个启用输入的解锁各为 197 字节，1 字节的差异来自赞助输入的原生签名编码。开发求值器测得第一个启用输入的主栈峰值为 7 项，备用栈峰值为 34 项，两栈载荷峰值为 359 字节。 [统一测量口径](../../docs/benchmark.zh-CN.md)
