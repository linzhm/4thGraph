# P2PKH-R1 Forth 探索版 0.1.0-alpha.2

[项目说明](../../README.zh-CN.md) · [原曲线生成器](../../reference/curve_compiler.py) · [原 v0.2.0 交易模板](../../template/v0.2.0/layout.json)

## 完整 R1 锁

4thGraph v0.2.0 读取 [r1.fth](r1.fth)。Forth 源码定义见证解析、输入授权、P‑256 验签和原生交易绑定。编译时执行的 `op-*` 词各发出一条 Script 指令，窗口循环由源码声明次数并展开。原 Python 生成器和汇编用于对照。

| 产物 | v0.2.0 / Forth 基线 | Forth 优化 |
| --- | ---: | ---: |
| 完整零值收款模板 | 46,302 B | 45,776 B |
| OTDA 重建程序 | 3,913 B | 3,910 B |

关闭优化时，Forth 锁和 OTDA 重建程序逐字节复现原模板。开启优化后，倍点入口用 ScriptNum 坐标 `z` 直接驱动 `OP_IF`，并用 `OP_2DUP` 复制栈顶的 `y z`。在 BSV Node 和 chain-gang 所用规则下，零坐标与非零坐标的分支行为一致。每处倍点省两条指令，完整锁含 263 处，共省 **526 B**。探索版使用独立版本号，现有钱包按已登记的模板字节识别输出。

两版各复放三种两进两出付款。表中入金含两个 R1 锁，付款也创建两个 R1 锁。OTDA 使用各模板自己的重建程序。耗时为每笔付款七次验证的中位数，栈峰值为整笔各输入的两栈载荷最大值。

| 模式 | 付款字节，基线 / 优化 | 入金加付款字节，基线 / 优化 | 两栈峰值字节，基线 / 优化 | Node RPC ms，基线 / 优化 | chain-gang ms，基线 / 优化 |
| --- | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | 93,374 / 92,322 | 186,124 / 184,020 | 3,479 / 3,478 | 50.20 / 50.01 | 14.95 / 13.21 |
| OTDA ALL | 101,250 / 100,192 | 194,000 / 191,889 | 185,614 / 183,510 | 51.26 / 56.54 | 13.39 / 14.40 |
| OTDA SINGLE | 101,179 / 100,121 | 193,929 / 191,818 | 93,005 / 91,953 | 52.20 / 50.26 | 13.02 / 13.84 |

六笔入金和六笔付款均通过双引擎验证并入块。沿用签名修改锁定时间的六笔付款均被拒绝。优化锁还通过了 BSV Node 的 1,296 个现有付款判定、chain-gang 的 432 个付款判定和 24 个畸形见证反例。 [验收矩阵](../../reference/acceptance.md)

### 完整锁复跑

从仓库根目录运行。复放使用装有 `ecdsa`、参考实现依赖和 [Chronicle chain-gang 固定版本](../../../../shared/requirements-chronicle.txt) 的 Python 环境。省略收款哈希时，编译器生成用于比较的零值收款模板。

```sh
project=projects/p2pkh-r1
experiment="$project/experiments/forth"
export PYTHONPATH=".:projects/4thgraph:$project/reference"

python "$experiment/compile_r1.py" --version
python "$experiment/compile_r1.py"
python "$experiment/compile_r1.py" --optimize --owner-hash160 "$R1_OWNER_HASH160"
bash shared/verify_node.sh --profile raised -- \
  python "$experiment/replay_r1.py" --matrix --output /tmp/r1-forth-comparison.json
```

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
bash shared/verify_node.sh --profile raised -- \
  python "$experiment/compare.py" --regtest --output /tmp/p256-forth-comparison.json
```

编译输出含 Forth 源码与生成字节的 SHA-256。regtest 报告还含部署和花费数据、最大栈载荷、两套引擎的验证耗时中位数及入块结果。
