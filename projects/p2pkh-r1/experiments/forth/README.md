# P2PKH-R1 Forth v0.3.0 探索版

[项目说明](../../README.zh-CN.md) · [原曲线生成器](../../reference/curve_compiler.py) · [原 v0.2.0 交易模板](../../template/v0.2.0/layout.json)

## 完整 R1 锁

4thGraph v0.2.0 读取 [r1.fth](r1.fth)。Forth 源码定义见证解析、输入授权、P‑256 验签和原生交易绑定。编译时执行的 `op-*` 词各发出一条 Script 指令，窗口循环由源码声明次数并展开。原 Python 生成器和汇编用于对照。

v0.3.0 是完整锁的 Forth 优化构建。编译器的 `--optimize` 选择 v0.3.0，默认构建逐字节复现 v0.2.0 的锁和 OTDA 重建程序。构建 JSON 用 `lock_version` 标记实际选中的锁。

开启优化后，倍点入口用计算产生的 ScriptNum 坐标 `z` 直接驱动 `OP_IF`，并用 `OP_2DUP` 复制栈顶的 `y z`。每处倍点省两条指令，完整锁含 263 处，共省 **526 B**。

### 同环境对照

三版使用同一组测试密钥、金额、交易形状和 v2 交易。sCrypt 1.20.0 `-O` 版替换同算法的点加和倍点内核，沿用相同的四位窗口和交易绑定。OTDA 使用各模板自己的重建程序。表中付款均为两进两出。 [sCrypt 原始夹具](https://github.com/linzhm/bsv-script-lab/pull/45)

| 构建 | 完整锁 | OTDA 重建程序 | ForkID ALL | OTDA ALL | 配对 OTDA SINGLE |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.2.0 基线 | 46,302 B | 3,913 B | 93,374 B | 101,250 B | 101,179 B |
| Forth v0.3.0 | **45,776 B** | **3,910 B** | **92,322 B** | **100,192 B** | **100,121 B** |
| sCrypt `-O` 内核 | 66,265 B | 4,022 B | 133,304 B | 141,406 B | 141,331 B |

在 BSV Node 1.2.3 `raised` 配置和固定 chain-gang `74676b9` 上，九笔入金和九笔付款均通过双引擎并入块。沿用签名修改锁定时间的九个对照均被拒绝。复放 JSON 记录原始交易、验证耗时中位数和两栈峰值。本轮耗时随模式和引擎变化。

### 输入与内部范围

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
bash tools/verify_node.sh --profile raised -- \
  python "$experiment/replay_r1.py" --matrix --output /tmp/r1-forth-comparison.json
```

三版对照在同时包含本实验和 #45 夹具提交 `89d90e0` 的临时检出中运行。使用 #45 固定的 Linux x86-64 sCrypt 编译器。 [夹具提交](https://github.com/linzhm/bsv-script-lab/commit/89d90e0b6be95b9dbb34bb09475417f210c8da3a)

```sh
GHCRTS=-N2 bash tools/verify_node.sh --profile raised -- \
  python "$experiment/replay_r1.py" --matrix --scryptc "$SCRYPTC" \
  --output /tmp/r1-forth-v030-comparison.json
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
bash tools/verify_node.sh --profile raised -- \
  python "$experiment/compare.py" --regtest --output /tmp/p256-forth-comparison.json
```

编译输出含 Forth 源码与生成字节的 SHA-256。regtest 报告还含部署和花费数据、最大栈载荷、两套引擎的验证耗时中位数及入块结果。
