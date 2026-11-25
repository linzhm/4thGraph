# 完整交易基准与验收

[English](benchmark.md)

基准使用公开的确定性测试密钥，经各项目正常的签名入口生成完整交易。
BSV Node 1.2.3 在临时隔离的回归网络上用显式上一输出与规则标志验签，
另一份判定来自项目固定的 chain-gang 版本。JSON 记录每个引擎的判定、
序列化字节数、交易 ID 和锁定脚本指纹。两进两出样本另验证签名完成后更改
锁定时间会使原授权无效。

## 复现

使用 Python 3.12。为每个项目创建独立环境，解释器位于
`$bench_env/<项目>/bin/python`。安装项目参考实现要求的依赖和
`ecdsa==0.19.1`。WOTS+、ML-DSA-44 和原生锁基准使用
[共享 Chronicle 依赖](requirements-chronicle.txt)。原生锁独立的离线
示例使用自己的依赖。ML-DSA-44 需要 OpenSSL 3.5 或以上，
可通过 `ML_DSA_OPENSSL` 指定可执行文件。按
[SM2 参考指南](../projects/p2pkh-sm2/reference/README.zh-CN.md)
构建 Rust 签名器，并把路径设到 `SM2_SIGNED_DATA_SIGNER`。

在仓库根目录运行：

```sh
bash shared/verify_node.sh -- python -m shared.benchmark \
  --venvs-dir "$bench_env" --output "$bench_results"
python -m unittest shared.test_benchmark shared.test_layout shared.test_verify_node
```

可重复使用 `--project` 指定项目。`--alternate-venvs-dir` 在相同签名交易
上比较另一份固定的 chain-gang 版本。环境直接从对应提交安装依赖，以便核对
来源。`--chain-only` 和 `--bench-only` 用于定位问题，报告会标明验收未完成。

## 指标说明

ForkID ALL 与 Chronicle OTDA ALL 均运行两进两出、三进两出和两进三出的
完整交易。Deferred R1 的每个激活输入都必须有同索引输出。其输入边际是
增加一对激活输入和目标输出，输出边际是由赞助输入额外支付一个输出。
生命周期包括原生 P2PKH 入金、直接退出和加入一次周转的方案。
Deferred 的周转发生在激活后，使用普通 R1 模板。

总字节数包含 CompactSize、输入输出结构与脚本。原生签名的 DER 编码长度
会随交易变化。按阶段计费时，将每笔交易字节数乘以对应费率，再求和。
耗时是本地中位数，包含各自的 Python 接口或节点 HTTP 往返开销。
栈数据来自开发求值器的成功路径，载荷字节仅统计栈内的数据长度。

各项目的判定规则和用例范围来自其验收夹具。统一报告记录测试和子测试标识，
检查漏测、重复、跳过和失败。每项的规则和使用的引擎见相应项目的验收文档。
例如，节点激活检查使用夹具指定的规则上下文，SignedData 用例检查链下验签。

Lamport 和 WOTS+ 的基准使用 `durable_signer`，先在 SQLite 中提交
一次性密钥的领取记录，再调用签名器。签名器报错后仍保留占用记录。
同一算法的各模板使用同一份数据库和同一个公钥标识。恢复旧份数据库时，
应停用无法确认是否使用过的密钥。

## 已入金节点验证

两个回归网络均显式设置 Genesis 与 Chronicle 高度及节点强制要求的共识参数。
放宽配置再启用脚本回归所用的体积和验证时长覆盖值。每种配置使用新的隔离节点，
分别写入结果。

```sh
for profile in default raised; do
  bash shared/verify_node.sh --profile "$profile" -- \
    "$bench_env/ml-dsa/bin/python" -m shared.benchmark_admission ml-dsa \
    --output "$bench_results/$profile/ml-dsa.json"
done
```

测试先用节点钱包入金，再记录内存池判定，并检查生成的区块是否实际包含交易。
生成的证据区分入金、激活和退出。这里测量本地节点的代表性退出场景，
矿工节点的策略需要另行验证。
