# 按公开输入来源特化的 Groth16 对照

使用 CCTP 附件里同一把 BLS12-381 验证密钥和两份拆分证明。两组公开信号各有两个无符号 128 位标量。两份材料的曲线点被规范化成相同的仿射坐标后交给各生成器。每个配置在 BSV Node 1.2.3 regtest 独立部署并实际花费，chain-gang 使用仓库所固定的 Chronicle-aware 提交。

动态版对两组证明复用逐字节相同的锁。两种互换攻击分别替换公开信号和同时替换信号与匹配的 MSM 声明，两者仍保留原证明。混合版固定第一项，第二项在花费时提供。两份拆分证明的第一项不同，因此混合配置和固定配置各复放原始证明。另有两项固定、三项动态且两份证明都有效的回归用例。

交易绑定配置使用同一个公开输入数据包验证证明和后继输出。负例用有效证明和它的原见证，给出另一份证明的后继状态，并重新生成真实交易的原像。BSV Node 和 chain-gang 均拒绝该花费。

## nChain 仿射布局的花费时数据

[共同输入规格、算术证明和含上界端点的双引擎结果](../../nchain-equivalence.md)

| 数据 | nChain 原生仿射入口 | 4thGraph 仿射入口 |
| --- | --- | --- |
| 公开输入和证明 A、B、C | 花费提供，验证密钥固定 | 花费提供，验证密钥固定 |
| 公开输入 MSM | 见证携带标量乘法与求和的斜率，锁逐步核验 | 见证按两位窗口携带仿射斜率，锁逐步核验 |
| B 的 Miller 斜率 | 见证提供，锁核验椭圆曲线递推 | 见证提供，锁核验递推及子群 |
| 固定 Γ、Δ 的预计算数据 | 梯度内联，或通过见证打开锁中的承诺 | 线系数内联，或以定长包打开 SHA-256 承诺 |
| Fp12 辅助数据 | Miller 乘积逆元供最终幂使用 | 现有配对余数供等价判定使用 |

nChain 解锁器也可载入域模数，由锁检查该常量。4thGraph 将模数随锁固定。nChain 的固定基点和预计算 `e(α,β)` 也属于验证密钥，动态输入不会修改这些值。[nChain 解锁入口](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/script_types/unlocking_keys/groth16.py) · [nChain 验证入口](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/groth16/model/groth16.py)

## 仿射布局复放

同一轮复放的第一份 CCTP 证明如下。两份证明均复用各配置的同一把动态锁。两种仿射布局共四笔有效花费全部入块。整轮 20 笔有效花费通过双引擎，38 个负例被拒绝，包括互换公开信号及正确 MSM 斜率、改动 B 的 Miller 斜率，以及篡改任一固定配对线表。

| 配置 | 锁 B | 见证 B | 部署加花费 B | 两栈合计峰值 B | Node RPC ms | chain-gang ms |
|---|---:|---:|---:|---:|---:|---:|
| 4thGraph 动态，原紧凑版 | 430,116 | 1,092 | 431,442 | 5,862 | 155.05 | 38.99 |
| 4thGraph `affine-inline` | 400,698 | 13,671 | 414,602 | 29,428 | 133.48 | 34.53 |
| 4thGraph `affine-witness` | **375,721** | 39,786 | 415,741 | 69,461 | 142.96 | 35.39 |
| nChain 仿射，固定梯度在锁 | 416,850 | 26,569 | 443,653 | 26,331 | 189.98 | 67.45 |
| nChain 仿射，梯度在见证 | 397,222 | 39,888 | 437,344 | 39,378 | 202.67 | 74.28 |

`affine-inline` 把 MSM 和 B 点的斜率放进见证，较原紧凑版少 29,418 B 锁字节。`affine-witness` 进一步把 26,112 B 的固定线表包移入见证，以承诺及读取代码替代内联常量，锁再少 24,977 B。最小锁较原紧凑版少 **54,395 B（12.65%）**，较 nChain 线表见证布局少 **21,501 B（5.41%）**。在两种 4thGraph 仿射布局中，`affine-inline` 的总交易字节较低。`affine-witness` 锁的 SHA-256 为 `b9f438154b6d4f7f3906bc4cee52d38fb15c2620bac109bbb0b2d8e55321ad7c`。

## 结果

下表保留引入仿射见证前的基线。16 笔有效花费全部入块，双引擎拒绝了 18 个控制用例。两种动态调度的见证一致，紧凑调度节省 12,615 B 锁字节。[两份证明的逐笔数据](result.json)

| 配置 | 锁 B | 证明见证 B | 部署加花费 B | 两栈合计峰值 B | Node RPC ms | chain-gang ms |
|---|---:|---:|---:|---:|---:|---:|
| 4thGraph 固定 | 279,421 | 963 | 280,617 | 5,764 | 116.10 | 29.02 |
| 4thGraph 混合 | 387,931 | 1,076 | 389,240 | 5,862 | 154.23 | 38.43 |
| 4thGraph 动态，基础调度 | 442,731 | 1,092 | 444,057 | 5,862 | 168.58 | 44.12 |
| 4thGraph 动态，紧凑调度 | 430,116 | 1,092 | 431,442 | 5,862 | 172.99 | 42.02 |
| 4thGraph 动态加后继绑定 | 430,779 | 1,092 | 432,300 | 6,020 | 166.06 | 43.26 |
| CCTP 紧凑 | 422,270 | 1,113 | 423,617 | 10,271 | 175.21 | 50.81 |
| CCTP 窗口与 Γ 改写 | 400,348 | 1,113 | 401,695 | 10,270 | 158.46 | 44.65 |
| nChain 仿射，梯度在见证 | 397,222 | 39,888 | 437,344 | 39,378 | 210.89 | 80.10 |
| nChain 仿射，固定梯度在锁 | 416,850 | 26,569 | 443,652 | 26,331 | 207.45 | 69.95 |

在全部动态的配置中，4thGraph 紧凑版的总字节比受测两种 nChain 配置低约 1.35% 和 2.75%。CCTP 紧凑版和窗口版的总字节仍然更低。后继绑定案例还包括 160 B 的原像 push，完整解锁脚本与输出大小见原始数据。

## 测量口径

总字节计入每个配置的部署及一次有效花费。验证耗时是每个引擎交替复验七次的中位数，节点列包括 RPC 往返。两栈字节峰值由相同的开发求值器采样。

CCTP 紧凑版和窗口优化版分别与历史的 422,270 B、400,348 B 锁摘要一致。nChain 对照使用两个原生仿射配置。一个使用 1,600 位取模阈值，把预计算配对梯度放入见证。另一个使用阈值 1，把固定梯度放入锁。4thGraph 与 CCTP 显式验证证明点和子群。nChain 原生路径采用其上游验证覆盖。

固定输入的 **28.7%** 收益来自单独的五公开输入基准。固定路径的既有锁和见证仍可逐字节复现，本页的数字单独衡量 CCTP 的输入配置。[固定声明基准](../fixed-statement/README.md)

## Chronicle 专用操作码

同一验证密钥、同一组公开输入和证明见证，Genesis 版与 Chronicle 版首份 CCTP 证明的交易对照如下。

| 4thGraph 布局 | Genesis 锁 B | Chronicle 锁 B | 见证 B | Genesis 部署加花费 B | Chronicle 部署加花费 B |
| --- | ---: | ---: | ---: | ---: | ---: |
| 射影 | 430,116 | 425,231 | 1,092 | 431,442 | 426,556 |
| 仿射，线表内联 | 400,698 | 397,169 | 13,671 | **414,602** | 411,074 |
| 仿射，见证打开线表 | **375,721** | **370,562** | 39,786 | 415,741 | **410,581** |

Chronicle 压缩了定长取片和倍乘指令，见证线表布局因此同时获得最小锁与最小 4thGraph 路径字节。CCTP 窗口版在同一夹具下的路径为 401,694 B。Chronicle 对照中 20 笔正向花费入块，38 个负例被双引擎拒绝。Chronicle 专用锁另有 v1 正向花费，激活前同一见证被双引擎拒绝。

## 重跑

4thGraph 配置从 [`verifier.fth`](../../verifier.fth) 编译，构建记录包含 Forth 源码摘要。下方重跑命令同时生成 CCTP 与 nChain 对照。

准备 Python 3.12、`ecdsa`、`patch` 和仓库固定的 `shared/requirements-chronicle.txt`。从仓库根目录运行。准备器验证 CCTP 基线附件的摘要并恢复两个 CCTP 对照。

```sh
project=projects/4thgraph
verifier="$project/groth16-bls12-381"
build="$PWD/$project/build/groth16-bls12-381/public-inputs"
python "$project/cctp/prepare_reference.py" /path/to/cctp-groth16-4thgraph-0.2.0-baseline.zip "$build/reference"
git clone https://github.com/nchain-innovation/zkscript_package.git "$build/zkscript"
git -C "$build/zkscript" checkout --detach fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4
git clone --branch v0.1.3 https://github.com/nchain-innovation/elliptic_curves_package.git "$build/curves"
PYTHONPATH="$PWD:$project/cctp:$build/reference/projects/groth16/reference:$build/zkscript:$build/curves" \
  bash shared/verify_node.sh --profile raised -- \
  python "$verifier/benchmarks/public-inputs/replay_comparison.py" \
  --archive "$build/reference" --output "$build/comparison.json"
```

复放 Chronicle 构建时为 `replay_comparison.py` 加 `--script-era chronicle`，并另指定输出文件。

报告包含两份材料的摘要、验证密钥摘要、锁的编译配置、各笔锁与见证字节、入块高度、运行指标，以及所有反例的双引擎判定。
