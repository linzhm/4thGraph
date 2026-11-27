# Winterfell SHA-256 STARK 验证

[English](verification.en.md) · [项目](../README.zh-CN.md) · [发布清单](../versions/v0.2.0/manifest.json)

## 证明配置

宿主使用 Winterfell 0.13.1。Merkle 承诺、Fiat–Shamir transcript 和 FRI 固定使用 SHA-256。证明核验从公开的 `current` 连续递增 1,023 次并按模 2³² 回绕后，得到公开的 `next`。项目复用 BLAKE3 计数器的 Forth 源码、AIR 和 FRI 参数，使两种哈希配置可对同一关系做差分。该公开 AIR 无需可信设置，也没有见证掩码。 [共享计数器 AIR](../../stark-counter/docs/verification.zh-CN.md#声明与证明) · [SHA-256 适配器](../reference/src/hash.rs)

两个命令各自在编译时固定自己的验证配置。同一条公开声明下，两种证明互换均被拒绝。宿主按选择的验证配置解释 Winterfell 序列化的证明。

## SHA-256 编码

首字节区分哈希用途。`||` 表示字节拼接。域元素经 Winterfell f128 域的规范序列化，固定为 16 字节小端。`LE64` 为无符号 64 位小端计数器。摘要固定为 32 字节。

| 标签 | SHA-256 输入 | Winterfell 用途 |
| --- | --- | --- |
| `00` | `00 \|\| bytes` | 字节串哈希 |
| `01` | `01 \|\| element_0 \|\| …` | 域元素序列，包括轨迹叶子和 transcript 初始种子 |
| `02` | `02 \|\| left \|\| right` | 有序 Merkle 父节点和两个摘要的种子更新 |
| `03` | `03 \|\| digest_0 \|\| …` | 按协议顺序排列的摘要列表 |
| `04` | `04 \|\| seed \|\| LE64(counter)` | 随机币采样及 grinding |

Forth 词使用原生 `OP_SHA256`。轨迹行词接收两个域元素构成的 32 字节编码。摘要列表词接收已解析的有序列表。父节点和种子计数词校验操作数长度。完整验证器接入时还须解析域元素并校验范围，再把编码交给这些词。 [Forth 词](../hashes.fth) · [共用向量](../versions/v0.1.0/hash-vectors.txt)

## 复放

运行项目 README 的构建与验证命令。四组固定公开声明覆盖普通输入、达到最大值但未回绕，以及首步或末步回绕。复放检查固定的大小及哈希，并拒绝错误声明、替换或格式异常的证明。 [证明复放](../versions/v0.1.0/measurements.json)

以下命令可单独生成并验证末步回绕证明。

```sh
binary=projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256
proof=projects/stark-winterfell-sha256/workspace/wrap.proof
"$binary" prove 4294966273 "$proof"
"$binary" verify 4294966273 0 "$proof"
```

| 用例 | SHA-256 证明 |
| --- | ---: |
| 普通输入 | 34,924 B |
| 末值为最大值 | 35,885 B |
| 最后一步回绕 | 35,977 B |
| 第一步回绕 | 36,719 B |

独立 Script 复放使用合成前输出，验证五个摘要向量及十二个格式错误或被改动的输入。安装固定的 chain-gang 后，在仓库根目录运行。 [依赖固定值](../../../tools/requirements-chronicle.txt) · [原生复放证据](../versions/v0.1.0/hash-checks.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python3 projects/stark-winterfell-sha256/reference/hash_replay.py --native --check
```

## 在 BSV 核验轨迹开封

宿主先验证完整证明。`trace-opening CURRENT NEXT QUERY PROOF` 记录 Winterfell 验证器实际抽取的位置，`QUERY` 是位置排序、去重后的序号。命令展开主轨迹原有的批量开封，并按证明承诺的轨迹根复核该路径。

`opening.fth` 先哈希两个域元素组成的行，再调用 `merkle-sha256-root #13 02`。编译器固定深度和标签，只检查一次摘要长度、包长度与位置范围，随后在逐层折叠时消费尚未读取的路径后缀。最后一层省去切分和索引除法。应用锁通过 `--bind-bytes` 固定预期根。

8,192 个叶子的轨迹承诺需要 13 层兄弟摘要，原始路径为 416 B。三把开封锁均为 368 B，见证脚本为 454–455 B，开发求值器测得双栈载荷峰值为 483–484 B。BSV Node 与 chain-gang 在合成前输出上接受三份开封，拒绝 27 个反例，包括错误行、兄弟顺序变化、错误长度和错误或非规范位置。 [开封锁](../opening.fth) · [编译器语法](../../../docs/language/syntax.md#33-有界-sha-256-merkle-路径) · [双引擎实测](../versions/v0.2.0/opening-checks.json)

```sh
binary=projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256
"$binary" trace-opening 4294966273 0 0 projects/stark-winterfell-sha256/workspace/wrap.proof

PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python3 projects/stark-winterfell-sha256/reference/opening_replay.py --binary "$binary" --native --check
```

## 开封锁对照

基线在同一把 13 层开封锁中使用 v0.1.0 带检查的父节点哈希。逐层替换此段代码，单层从 19 B 降至 5 B。两种实现共用同一份证明、轨迹行、路径、索引和根。两种实现在双引擎上各接受三份有效开封并拒绝 27 个反例。 [对照脚本](../reference/compare_openings.py) · [版本实测](../versions/v0.2.0/opening-comparison.json)

| 指标 | 带检查的父节点基线 | 专用父节点 |
| --- | ---: | ---: |
| 锁脚本 | 550 B | 368 B |
| 锁与解锁脚本字段的序列化大小 | 1,010–1,011 B | 828–829 B |
| 解锁脚本 | 454–455 B | 454–455 B |
| 开发求值器两栈载荷峰值 | 483–484 B | 483–484 B |

节省的 182 B 占锁脚本的 33.1%，占含 CompactSize 长度前缀的两个脚本字段的 18.0%。每份开封以交替顺序运行 201 组成对样本。本轮 chain-gang 的成对耗时差中位数为 4.1–6.8 µs，包含解析时间。BSV Node 的成对耗时差中位数为 21.8–42.4 µs，包含 `verifyscript` RPC 耗时。计时使用合成前序输出。证明生成与完整 STARK 验证由宿主执行。

构建发布二进制后，在仓库根目录运行。依赖与原生开封复放相同。

```sh
binary=projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python3 projects/stark-winterfell-sha256/reference/compare_openings.py --binary "$binary"
```

复放将新实测写入 `projects/stark-winterfell-sha256/workspace/build/opening-comparison.json`。

## 交易验证

开封锁核验指定位置的叶子是否属于预期根。完整 Script 验证器还需要从链上 transcript 推导该位置并完成 AIR 和 FRI 检查。进入交易应用后，secp256k1 原像断言再把公开状态和输出绑定到实际花费。 [PELS 锁的交易绑定](../../../docs/pels-locks.zh-CN.md)
