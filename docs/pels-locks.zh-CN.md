# 编译和组装 PELS 锁

[English](pels-locks.md) · [Forth 标准库](language/stdlib.zh-CN.md)

通过 `REQUIRE stdlib/pels.fth` 在 Forth 中表达输入数、完整有序输出以及交易字段断言。独立锁支持一个输入和构建期计算的输出。[结算夹具](../projects/workflow-examples/pels-settle.fth)要求付款、回执和锁定时间 42。

`IF` 的条件须在构建期求值为 Forth `cell`。编译器执行所选分支，并保留该分支中验证的断言。

## 编译目标

`--target` 选择交易版本，`--sighash-family` 选择 `bip143`、`otda`、`both` 或 `auto`。编译器先核对覆盖，再比较链接后锁和见证字段的序列化成本，包括长度前缀。当前实现的前序金额断言需要 BIP143。

编译时检查输出总额是否超出货币上限或固定的前序输出金额。组装见证时，各签名哈希模式都会检查实际前序输出的金额能否覆盖输出总额。

```sh
export PYTHONPATH=src:.
python3 -m fourthgraph.workflow.protocol projects/workflow-examples/pels-settle.fth \
  --entry settle --bind-bytes recipient-lock=51 --target chronicle-v2 \
  --sighash-family auto --explain > lock.json
python3 -m fourthgraph.workflow.protocol pels-witness lock.json \
  --parent parent.hex --unsigned unsigned.hex
```

编译示例使用合成夹具输出。组装时需提供实际父交易和匹配的未签候选，文件均使用交易序列化的十六进制。双模式构建在组装时用 `--sighash-family bip143` 或 `--sighash-family otda` 指定已编入的路径。产物保留精确 Script、候选、片段的范围与哈希，以及各路径的见证布局。用实际父交易和适用的链规则独立验收组装结果。[验收测试](../tests/test_pels_lock.py)

## 动态后继

动态构建把应用规则链接到内置的 `pels-verify` 模板。规则的 Forth 构建期栈效果为 `( script -- script )`。发射的规则代码接收当前五字节状态和经过认证的前序金额（ScriptNum），按标准库的栈契约留下后继的五字节状态和八字节小端金额。规则的运行时行为需要在评审和测试中用实际前序输出来验证。

```sh
python3 -m fourthgraph.workflow.protocol status.fth --entry status-rule \
  --pels-successor-state 0300000000 --target chronicle-v2 \
  --sighash-family auto --explain > successor.json
python3 -m fourthgraph.workflow.protocol pels-witness successor.json \
  --parent parent.hex --unsigned unsigned.hex > spend.json
```

此模板用 BIP143 ALL 认证前序金额。对 Chronicle 目标，`auto` 选择 BIP143 并记录排除 OTDA 的原因。显式指定 `otda` 或 `both` 原像策略会失败。交易版本由目标决定，并在 Script 中断言。

用同一规则和目标分别编译各个状态。产物记录精确的前序输出 Script 及其 `scriptCode` 锚点。组装器检查交易花费该前序输出，且唯一后继输出沿用相同代码。实际前序输出的金额必须覆盖后继金额。后继状态和金额是否符合规则由独立的 Script 验证决定。可执行夹具用两笔合成交易验收草稿到就绪、就绪到草稿的转换，并用固定版本的 chain-gang 验证拒绝用例。[夹具源码和验收测试](../tests/test_pels_successor_library.py)
