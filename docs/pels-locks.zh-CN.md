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
