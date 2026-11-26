# P2PKH-R1 历史实验与交易基准

[项目说明](../../README.zh-CN.md) · [原曲线生成器](../../reference/curve_compiler.py) · [原 v0.2.0 交易模板](../../template/v0.2.0/layout.json)

## 完整 R1 锁

点加、倍点用 `formula:` 写成带名称的 P‑256 公式。Forth 源码声明坐标范围 `[1 - p, p)` 及栈底固定的 `p` 和 `3b mod p`，由编译器推导中间结果范围并检查返回值。整锁先把外部公钥坐标解码为规范的 ScriptNum，再在进入公式前检查取值范围。内部坐标来自固定常量或有符号取余，倍点遇到 `z = 0` 时原样保留输入。验签流程中的窗口、见证解析及交易绑定沿用原模板。 [Forth 源码](r1.fth) · [公式语法](../../../../docs/language/specification.md#钱包锁中的数值公式)

开启 `--optimize` 后，4thGraph 比较运算顺序、操作数摆放和栈项的最后一次使用。编译器还尝试展开交叉乘积、将乘二改成加法，以及把读取栈底模数和取余合在一起调度。构建 JSON 记录每个候选的字节数、选中的改写和中间量位宽上界。字节级测试将相对手工基线的差额定位到 135 处点加和 263 处倍点。点加每处从 147 B 降到 123 B，倍点含无穷远分支从 76 B 降到 74 B。

| 构建 | 完整锁 | OTDA 重建程序 | BIP143 ALL | OTDA ALL | 配对 OTDA SINGLE |
| --- | ---: | ---: | ---: | ---: | ---: |
| 手工基线 v0.2.0 | 46,302 B | 3,913 B | 93,374 B | 101,250 B | 101,179 B |
| Forth v0.3.0 | 45,776 B | 3,910 B | 92,322 B | 100,192 B | 100,121 B |
| 同一份 v0.4.0 Forth，关闭优化 | 117,775 B | 4,305 B | 236,324 B | 244,992 B | 244,917 B |
| 同一份 v0.4.0 Forth，开启优化 | **42,536 B** | **3,886 B** | **85,842 B** | **93,664 B** | **93,593 B** |

表中付款使用两进两出、相同的测试密钥和金额，以及各自锁对应的 OTDA 重建程序。BSV Node 1.2.3 在 `raised` regtest 配置下验证了 **12 笔入金和 12 笔付款**并全部入块。固定的 chain-gang `74676b9` 独立通过这 24 笔交易。沿用原签名修改锁定时间的 12 笔反例均被两套引擎拒绝。

优化版通过 Node 的 1,296 项付款判定和 chain-gang 的 432 项付款判定，并通过 4 项有效见证对照和 24 项畸形见证拒绝用例。两种内核还各比较 153 组坐标，覆盖负余数、范围端点和零坐标，结果的有符号 ScriptNum 编码与 v0.3.0 一致。一次复放中，开发求值器测得 BIP143 ALL 两栈合计峰值由手工基线的 3,477 B 增至 3,642 B。验证耗时随引擎和模式变化。 [验收矩阵](../../reference/acceptance.md)

### v0.3.0 与 sCrypt 历史对照

v0.3.0 的源码在 263 处倍点直接用已计算的 `z` 驱动 `OP_IF`，并用 `OP_2DUP` 复制 `y z`，共省 526 B。历史源码由钱包库保留。 [v0.3.0 源码](../../../../src/fourthgraph/stdlib/wallet/r1.fth)

三版使用同一组测试密钥、金额、交易形状和 v2 交易。sCrypt 1.20.0 `-O` 版替换同算法的点加和倍点内核，沿用相同的四位窗口和交易绑定。OTDA 使用各模板自己的重建程序。表中付款均为两进两出。 [sCrypt 原始夹具](https://github.com/linzhm/bsv-script-lab/pull/45)

| 构建 | 完整锁 | OTDA 重建程序 | BIP143 ALL | OTDA ALL | 配对 OTDA SINGLE |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.2.0 基线 | 46,302 B | 3,913 B | 93,374 B | 101,250 B | 101,179 B |
| Forth v0.3.0 | **45,776 B** | **3,910 B** | **92,322 B** | **100,192 B** | **100,121 B** |
| sCrypt `-O` 内核 | 66,265 B | 4,022 B | 133,304 B | 141,406 B | 141,331 B |

在 BSV Node 1.2.3 `raised` 配置和固定 chain-gang `74676b9` 上，九笔入金和九笔付款均通过双引擎并入块。沿用签名修改锁定时间的九个对照均被拒绝。复放 JSON 记录原始交易、验证耗时中位数和两栈峰值。本轮耗时随模式和引擎变化。

### v0.3.0 验收记录

锁在见证进入曲线点运算前检查栈形状、字段长度、授权类型、公钥、标量和逆元。窗口索引由检查后的标量推导。独立窗口词的 `--assume-input-ranges` 不参与完整锁构建。v0.3.0 的字节改动仅出现在 263 处倍点，完整锁每条成功路径仍经过所有授权检查。基线和 v0.3.0 在双引擎上通过 16 个正例和 216 个畸形输入对照，覆盖越界标量、异常逆元宽度、非法曲线点和见证栈形状。v0.3.0 另通过 Node 的 1,296 个付款判定、chain-gang 的 432 个付款判定和 24 个畸形见证反例。 [验收矩阵](../../reference/acceptance.md)

### 完整锁复跑

从仓库根目录运行。复放使用装有 `ecdsa`、参考实现依赖和 [Chronicle chain-gang 固定版本](../../../../tools/requirements-chronicle.txt) 的 Python 环境。省略收款哈希时，编译器生成用于比较的零值收款模板。

```sh
project=projects/p2pkh-r1
experiment="$project/experiments/forth"
export PYTHONPATH="src:.:$project/reference"

python "$experiment/compile_r1.py" --version
python "$experiment/compile_r1.py"
python "$experiment/compile_r1.py" --optimize --owner-hash160 "$R1_OWNER_HASH160"
python -m unittest discover -v -s "$experiment" -p test_compile_r1.py
bash tools/verify_node.sh --profile raised -- \
  python "$experiment/replay_r1.py" --matrix --output /tmp/r1-forth-comparison.json
```

可附加 sCrypt 对照。此项需要 #45 夹具提交 `89d90e0` 和该夹具固定的 Linux x86-64 sCrypt 编译器。 [夹具提交](https://github.com/linzhm/bsv-script-lab/commit/89d90e0b6be95b9dbb34bb09475417f210c8da3a)

```sh
GHCRTS=-N2 bash tools/verify_node.sh --profile raised -- \
  python "$experiment/replay_r1.py" --matrix --scryptc "$SCRYPTC" \
  --output /tmp/r1-forth-scrypt-comparison.json
```

## 点乘窗口候选

[`msm.fth`](msm.fth) 声明 `P256.mul2(u,G,v,Q)` 和数值范围。编译器核对实际锁前缀使用经过验收的公钥检查和标量推导，再从范围分析得到标量位宽和查表下标范围。扫描通过窗口宽度计算各调用点的次数，在生成或展开循环字节前报告证据和缺少的前提。

从仓库根目录运行，使用上面的 Python 环境和 `PYTHONPATH`。

```sh
cmd="$experiment/msm_experiment.py"
python "$cmd" scan
python "$cmd" scan --format json --output /tmp/r1-scan.json
python "$cmd" local --candidate split-4-affine-g
python "$cmd" build --candidate split-4-affine-g --output /tmp/r1-affine-build.json

bash tools/verify_node.sh --profile raised -- \
  python "$cmd" compare --workflow guided --budget 4 --full-budget 4 --vectors 32 \
  --output /tmp/r1-guided.json --markdown /tmp/r1-decision.md --evidence /tmp/r1-payments.json
```

用 `--candidate split-N` 试分表，`split-NxM` 试两个不同宽度，`joint-N` 试联合表。分表可加 `-affine-g` 试固定表点加的局部替换。后端检查标量位宽、表大小和可用的仿射前提，例如 `joint-2-affine-g` 会指向没有统一 `Z=1` 保证的查表位置。比较时可重复传入 `--candidate`，也可使用自动从扫描选出的试验。降低 `--full-budget` 时，候选按静态成本入围，最终各目标只按实测选优。`--matrix` 为已复放候选追加完整签名和畸形见证矩阵。

三个校准构造用相同两进两出付款复放。混合宽度 `split-5x4` 比 `split-4` 少执行 12 个循环点加，尽管表初始化大了 1,085 B，锁仍短 265 B。联合表 `joint-2` 的锁比混合宽度大 657 B，重复结构使 OTDA 重建程序短 2,452 B。每个输入都携带重建程序，因此两进两出的 OTDA ALL 付款短 3,590 B。

扫描发现 `split-4` 有 64 个点加位置可用固定 `G` 表的仿射性质。重写绑定点加公式的右侧 `Z` 为 1，并对零下标单独跳过点加。每处内核与查表共省 12 B，分支增加 5 B，整锁净省 448 B。重建程序增加 128 B，其中包含新的内核字典。此规则适用于能证明非零表项的 `Z=1` 且能单独处理无穷远的表。若要优化 OTDA，需同时核算每个输入增加的字典字节。

| 构造 | 完整锁 | BIP143 ALL | OTDA ALL | 配对 OTDA SINGLE |
| --- | ---: | ---: | ---: | ---: |
| `split-4` | 41,986 | 84,742 | 92,672 | 92,601 |
| `split-5x4` | 41,721 | 84,212 | 95,282 | 95,211 |
| `joint-2` | 42,378 | 85,526 | **91,692** | **91,621** |
| `split-4-affine-g` | **41,538** | **83,846** | 92,032 | 91,961 |

比较 JSON 并列给出估算、实测、两栈载荷峰值和淘汰原因。`--workflow explicit` 使用三个校准构造加上此前已知的 `split-5` 作为同预算对照。`--reference PATH` 读取先前的比较 JSON，核对校准值并用其候选清单界定新方案。计时从进入编译前端开始，分别记录首个局部验证、首个双引擎结果和实测决策，包含验证开销。启动 node 和 Agent 阅读、思考及编写规则的时间在计时范围之外。

## 点运算内核 0.1.0-alpha.1

4thGraph v0.2.0 从 [p256.fth](p256.fth) 编译 P‑256 射影点加与倍点。两词沿用原生成器的算术公式和有符号余数。入口按从栈底到栈顶的顺序接收正域模数 `p`、曲线常量 `3b mod p` 和点坐标，返回这两个常量及结果的三个坐标。倍点在 `z = 0` 时保留原输入。实验编译器提供显式 ScriptNum 运算和静态深度栈操作，普通 Forth cell 仍按 64 位运算。

此前的内核实验单独验证算术和承诺算术输出的测试交易。每次调整 Forth 时可用 `--source` 指向候选并复跑比较。报告记录两版脚本摘要、字节差值、两栈峰值以及各测试的判定。

### 同基线结果

| 算术内核 | 原生成器 | Forth | 变化 | 两栈合计峰值，原版 / Forth |
| --- | ---: | ---: | ---: | ---: |
| 点加 | 147 B | 148 B | +1 B | 869 B / 869 B |
| 倍点 | 76 B | 76 B | 0 B | 871 B / 871 B |

把倍点中的 `over over` 改成 `2dup` 省了 1 B。两个候选均通过每个内核的 153 组算术差分，以及生成元、互逆点和无穷远点相关的 7 组曲线向量。BSV Node 1.2.3 和固定版本 chain-gang 验证了四笔原版与 Forth 的内核测试花费，均实际入块。零模数和缺少输入的八个反例均被拒绝。两栈峰值由开发求值器采样。

### 复跑

从仓库根目录使用同一环境运行。

```sh
python "$experiment/compile_p256.py" --version
python "$experiment/compile_p256.py"
python "$experiment/compare.py"
bash tools/verify_node.sh --profile raised -- \
  python "$experiment/compare.py" --regtest --output /tmp/p256-forth-comparison.json
```

编译输出含 Forth 源码与生成字节的 SHA-256。regtest 报告还含部署和花费数据、最大栈载荷、两套引擎的验证耗时中位数及入块结果。

## Complete transactions and stack measurements

The v0.1.0 and v0.2.0 figures use deterministic fixtures at `beeb4dd`. The Forth v0.3.0 rows come from funded regtest transactions that BSV Node 1.2.3 mined and chain-gang `74676b9` independently verified. Sizes are in bytes. Script sizes follow input and output order, and `× n` indicates n equal sizes. The development evaluator measures peak main-stack items, altstack items, and combined payload for input zero.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `v0.1.0` · `0x41` | 2×2 | 59,582 × 2 | 326 × 2 | 59,582 × 2 | 119,934 | 122 / 133 | 4,146 |
| `v0.1.0` · `0x61` | 2×2 | 59,582 × 2 | 119,454 × 2 | 59,582 × 2 | 358,194 | 122 / 133 | 238,734 |
| `compiled-literal` · `0x41` | 2×2 | 47,510 × 2 | 326 × 2 | 47,510 × 2 | 95,790 | 111 / 131 | 3,471 |
| `compiled-literal` · `0x61` | 2×2 | 47,510 × 2 | 95,310 × 2 | 47,510 × 2 | 285,762 | 111 / 131 | 190,446 |
| `compiled-reconstructed` · `0x41` | 2×2 | 47,510 × 2 | 326 × 2 | 47,510 × 2 | 95,790 | 111 / 131 | 3,473 |
| `compiled-reconstructed` · `0x61` | 2×2 | 47,510 × 2 | 6,176 × 2 | 47,510 × 2 | 107,490 | 111 / 131 | 190,446 |
| `compiled-shared-kernels` · `0x41` | 2×2 | 47,510 × 2 | 326 × 2 | 47,510 × 2 | 95,790 | 111 / 131 | 3,479 |
| `compiled-shared-kernels` · `0x61` | 2×2 | 47,510 × 2 | 4,272 × 2 | 47,510 × 2 | 103,682 | 111 / 131 | 190,446 |
| `v0.2.0` · `0x41` | 2×2 | 46,302 × 2 | 326 × 2 | 46,302 × 2 | 93,374 | 113 / 131 | 3,479 |
| `v0.2.0` · `0x61` | 2×2 | 46,302 × 2 | 4,264 × 2 | 46,302 × 2 | 101,250 | 113 / 131 | 185,613 |
| `compiled + v0.2.0` · `0x61` · before | 2×2 | 46,302 / 47,510 | 50,549 × 2 | 46,302 / 47,510 | 195,028 | 113 / 131 | 188,029 |
| `compiled + v0.2.0` · `0x61` · after | 2×2 | 46,302 / 47,510 | 8,186 × 2 | 46,302 / 47,510 | 110,302 | 113 / 131 | 188,030 |
| `compiled + v0.2.0` · `0xe1` · before | 2×2 | 46,302 / 47,510 | 50,507 × 2 | 46,302 / 47,510 | 194,944 | 113 / 131 | 187,947 |
| `compiled + v0.2.0` · `0xe1` · after | 2×2 | 46,302 / 47,510 | 8,144 × 2 | 46,302 / 47,510 | 110,218 | 113 / 131 | 187,947 |
| `v0.2.0` · `0x63` · after | 2×2 | 46,302 × 2 | 4,224 / 4,233 | 46,302 × 2 | 101,179 | 113 / 131 | 92,987 |
| `v0.2.0` · `0xe3` · after | 2×2 | 46,302 × 2 | 4,182 / 4,191 | 46,302 × 2 | 101,095 | 113 / 131 | 92,905 |
| Forth v0.3.0 · `0x41` | 2×2 | 45,776 × 2 | 326 × 2 | 45,776 × 2 | 92,322 | 113 / 131 | 3,478 |
| Forth v0.3.0 · `0x61` | 2×2 | 45,776 × 2 | 4,261 × 2 | 45,776 × 2 | 100,192 | 113 / 131 | 183,510 |
| Forth v0.3.0 · `0x63` | 2×2 | 45,776 × 2 | 4,221 / 4,230 | 45,776 × 2 | 100,121 | 113 / 131 | 91,935 |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `v0.1.0` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 59,593 (59,582 / 0 / 11) | 120,160 | 240,093 |
| `v0.1.0` · `0x61` | 3×2 | 119,622 (0 / 119,577 / 45) | 2×3 | 178,779 (59,582 / 119,186 / 11) | 120,173 | 478,367 |
| `compiled-literal` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 47,521 (47,510 / 0 / 11) | 96,015 | 191,806 |
| `compiled-literal` · `0x61` | 3×2 | 95,478 (0 / 95,433 / 45) | 2×3 | 142,563 (47,510 / 95,042 / 11) | 96,029 | 381,791 |
| `compiled-reconstructed` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 47,521 (47,510 / 0 / 11) | 96,016 | 191,806 |
| `compiled-reconstructed` · `0x61` | 3×2 | 6,342 (0 / 6,299 / 43) | 2×3 | 47,601 (47,510 / 80 / 11) | 96,030 | 203,520 |
| `compiled-shared-kernels` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 47,521 (47,510 / 0 / 11) | 96,016 | 191,806 |
| `compiled-shared-kernels` · `0x61` | 3×2 | 4,438 (0 / 4,395 / 43) | 2×3 | 47,601 (47,510 / 80 / 11) | 96,030 | 199,712 |
| `v0.2.0` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 46,313 (46,302 / 0 / 11) | 93,600 | 186,973 |
| `v0.2.0` · `0x61` | 3×2 | 4,430 (0 / 4,387 / 43) | 2×3 | 46,393 (46,302 / 80 / 11) | 93,614 | 194,864 |
| `compiled + v0.2.0` · `0x61` · before | 3×2 | 50,715 (0 / 50,672 / 43) | 2×3 | 48,793 (46,302 / 2,480 / 11) | 94,822 | 289,850 |
| `compiled + v0.2.0` · `0x61` · after | 3×2 | 8,352 (0 / 8,309 / 43) | 2×3 | 46,393 (46,302 / 80 / 11) | 94,821 | 205,124 |
| `compiled + v0.2.0` · `0xe1` · before | 3×2 | 50,550 (0 / 50,507 / 43) | 2×3 | 48,793 (46,302 / 2,480 / 11) | 94,740 | 289,683 |
| `compiled + v0.2.0` · `0xe1` · after | 3×2 | 8,187 (0 / 8,144 / 43) | 2×3 | 46,393 (46,302 / 80 / 11) | 94,740 | 204,958 |
| `v0.2.0` · `0x63` · after | 3×2 | 455 (0 / 412 / 43) | 2×3 | 46,313 (46,302 / 0 / 11) | 93,555 | 194,733 |
| `v0.2.0` · `0xe3` · after | 3×2 | 373 (0 / 330 / 43) | 2×3 | 46,313 (46,302 / 0 / 11) | 93,472 | 194,567 |

[Unified benchmark and reproduction](../../../../docs/benchmark.md) · [Matched sCrypt comparison](../../docs/scrypt-matched.en.md)
