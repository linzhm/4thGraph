# 与 nChain 仿射 Groth16 验证锁的等价性

对照的是 nChain `zkscript_package` 的 BLS12-381 原生仿射 `groth16_verifier`，固定提交 `fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4`。两个锁各用自己的见证编码，验证同一把验证密钥、同一组公开标量和同一组证明点。对照关闭应用签名、后继约束和额外栈接口，nChain 的 `extractable_inputs` 为 0。[上游 verifier](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/groth16/model/groth16.py)

## 共同规格

- 部署固定 `VK=(α,β,γ,δ,IC[0…n])`。共同域内，验证密钥各点有限且属于对应的 r 阶子群。
- 花费提交有序标量 `s[1…n]` 和有限证明点 `A,C ∈ G1`、`B ∈ G2`，坐标和标量取规范表示。对照的逐槽范围是闭区间 `[0,2^128]`，配对输入使用共同支持的有限点 `V=IC[0]+Σ[s[i]]IC[i]`。
- 验证条件为 `e(A,B)=e(α,β)·e(V,γ)·e(C,δ)`。花费者可提供辅助计算，Script 核对斜率或承诺后使用。两种锁都可把固定 Γ、Δ 的预计算数据内联，或允许花费者打开部署时的承诺。

4thGraph 的 `{"bits":128}` 表示 `[0,2^128−1]`。nChain 的编码器给出了等于 `max_multiplier` 的例子。新对照使用 `{"max":"340282366920938463463374607431768211456"}`，4thGraph 在 Script 内核对含端点的范围，每槽公开包用 17 字节。上游的 `max_multipliers` 同时用于选择展开轮数，本文的共同范围限定了所比较的数学声明。[nChain 标量编码](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/script_types/unlocking_keys/unrolled_ec_multiplication.py)

## 算术等价性

以下推导针对共同输入域和符合各自格式的完整算术见证。

**1. 两种 MSM 得到同一个 V。** nChain 从标量路径逐轮倍点与加点，再加 `IC[0]`。追加一位 `b` 的状态是 `T ← 2T + [b]IC[i]`。4thGraph 的第 j 个两位窗口预计算 `d·4^j·IC[i]` 的三个非零候选。Script 从公开标量取出 `d`，累加到从 `IC[0]` 初始化的状态。展开标量表示后，每一槽都贡献 `[s[i]]IC[i]`。

加点斜率满足 `m·(x₂−x₁)=y₂−y₁`，倍点斜率满足 `m·2y₁=3x₁²`。非零分母给出唯一斜率，后续坐标由 Weierstrass 群加法公式确定。单位元和逆点按群法处理。4thGraph 在零数位、单位元或逆点分支要求零占位斜率。合法见证可用宿主域求逆生成。[4thGraph 仿射递推](bls12381/affine_witness.py) · [nChain 曲线运算](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/elliptic_curves/ec_operations_fq.py)

**2. Miller 乘积表示同一个配对关系。** 记 nChain 的有符号 BLS seed 为 `u=−U`，正 seed 的 Miller 函数为 `f_U`，最终幂为 `E=(q^12−1)/r`。4thGraph 的 Miller 乘积是

    M = f_U(A,B) · f_U(−V,γ) · f_U(−C,δ) · f_U(−α,β)

有限 r 阶 G2 点的这段递推中，倍点与加点的分母非零。倍点处没有 2 阶点，非平凡加点前的倍数处于 1 和 r−1 之间。Miller 函数的负 seed 恒等式为 `f_(−U,Q)=(f_(U,Q)·v_([U]Q))^−1`。在扭曲坐标中，G1 的 x 坐标乘以 `w²∈Fq6`，G2 的 x 坐标在 `Fq2`，竖线的值位于 `Fq6`。两实现的线符号和投影尺度也只贡献 `Fq6*` 因子，最终幂将这些因子消除。任一配对参数取负也使配对取逆。由此 `M^E=1` 表示共同规格的等式。nChain 对三重配对及固定的 `e(α,β)` 使用同一取向，整体取逆保持等式。[4thGraph Miller 与固定项](bls12381/verifier.py) · [nChain 三重配对](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/bilinear_pairings/model/pairing.py)

**3. 最终幂与余数具有相同的单位元判定。** nChain 核对 Miller 乘积的见证逆元，再做 easy exponent `(q^6−1)(q²+1)`。跟踪 hard exponent 的平方、乘法、共轭和 Frobenius 得到

    h = (u−1)²(q³ + u·q² + (u²−1)(u+q)) + 3
      = 3(q⁴−q²+1)/r

上游注释标注通常的 hard exponent，以上倍数来自实际指令序列。左右两侧共同作用最终幂后落在 r 阶群，`gcd(3,r)=1`，所以再立方保持相等判定。[nChain 最终幂](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/bilinear_pairings/bls12_381/final_exponentiation.py)

4thGraph 验证存在 `z` 使 `Mz^(q+U) ∈ Fq6*`。在阶为 `N=q^6+1` 的循环商群 `Fq12*/Fq6*` 中，`gcd(q+U,N)=r`，所以该幂映射的像是商群的 r 次幂。设 `M=g^j` 且 `g` 生成 `Fq12*`。类 `[M]` 属于该像当且仅当 `r | j`，这也正是 `M^E=1`。反过来，等式成立时取 `a=q+U`、`z=M^(−a^−1 mod N/r)` 即得见证。循环平方和按位乘法累积 `z^U`，Frobenius 给出 `z^q`，最终检查结果属于非零 `Fq6`。非零条件排除零见证。[余数实现](bls12381/verifier.py) · [整数恒等式测试](tests/test_backend.py)

**4. 线表放置保持相同递推。** nChain 在见证模式核对固定梯度的链式 HASH256。4thGraph 在解码前核对有序、定长线系数包的 SHA-256。对同一部署密钥，在哈希承诺保持绑定的假设下，两者的见证模式各自解出与内联模式相同的线。动态斜率由 Script 逐步核对。[nChain 承诺检查](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/groth16/model/groth16.py#L44-L86) · [4thGraph 见证入口](bls12381/affine_witness.py)

## 规格边界

| 项目 | 实现及证据 |
| --- | --- |
| 证明点检查 | 4thGraph 在 Script 核对坐标、曲线及 A、B、C 子群，使用 BLS12-381 的特征等式。nChain 受测路径没有同一套显式子群门。数学比较以规范子群证明为输入。[快速子群检查](https://eprint.iacr.org/2019/814) |
| V 为无穷远点 | 4thGraph 处理单位配对并有正向回归。nChain 上游三重配对将无穷远配对输入列为未支持。这一情形属于 4thGraph 的扩展输入域。[上游三重配对说明](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/bilinear_pairings/model/pairing.py#L132-L178) |
| 公开标量全零 | V 可以仍然有限。上游高层见证构造器对中间单位元取斜率会失败。差分夹具用其底层解锁编码器省略该斜率，锁仍由上游原构建方式生成。[差分夹具](benchmarks/public-inputs/replay_equivalence.py) |
| 应用复用公开输入 | nChain 可从指定的标量见证提取数值，4thGraph 可用同一个经验证的公开包绑定后继输出。两种接口采用各自的应用语义，本对照关闭额外应用逻辑。[4thGraph 后继绑定](bls12381/verifier.py) |

本证据由验证关系的算术推导、源码映射和交易差分组成。对编译器与两个脚本解释器的全部原始栈状态，机器形式化等价性尚未建立。

## 同域改进

按包含 `2^128` 端点的共同范围比较第一份 CCTP 证明，字段与栈载荷均按实际字节计量。

| 配置 | 锁 B | 见证 B | 部署加一次花费 B | 两栈合计峰值 B |
| --- | ---: | ---: | ---: | ---: |
| 4thGraph 射影动态 | 430,943 | 1,094 | 432,270 | 5,862 |
| 4thGraph 仿射，线表内联 | 401,339 | 13,769 | 415,342 | 29,620 |
| nChain 仿射，梯度内联 | 416,850 | 26,569 | 443,653 | 26,331 |
| 4thGraph 仿射，见证打开线表 | **376,362** | 39,884 | 416,479 | 69,557 |
| nChain 仿射，见证打开梯度表 | 397,222 | 39,888 | 437,343 | 39,378 |

按相同的表放置比较，4thGraph 的内联锁小 **15,511 B（3.72%）**，见证版锁小 **20,860 B（5.25%）**。实现用两位窗口累计 G1 MSM，用配对余数替代通用最终幂，并用一次整包哈希核对固定线表。上表衡量组合收益，单项收益需要各自的消融对照。见证版的主要代价是两栈载荷峰值升到约 69.6 KB。

## 重跑

沿用两份 CCTP 真实证明、固定的 nChain 提交与椭圆曲线库、Node 1.2.3 及 Chronicle-aware chain-gang。补充纯 regtest 边界夹具，公开代数关系为 `IC=(5P,2P,3P)`、`α=7P`、`C=11P`、`B=β=γ=δ=Q`、`A=(23+2s+3t)P`。覆盖两个零、单槽零、两槽上界前一位，以及每槽各自等于上界。[依赖和归档准备](benchmarks/public-inputs/README.md#重跑)

```sh
project=projects/4thgraph
verifier="$project/groth16-bls12-381"
build="$PWD/$project/build/groth16-bls12-381/public-inputs"
PYTHONPATH="$PWD:$project/cctp:$build/reference/projects/groth16/reference:$build/zkscript:$build/curves" \
  bash shared/verify_node.sh --profile raised -- \
  python "$verifier/benchmarks/public-inputs/replay_equivalence.py" \
  --archive "$build/reference" --output "$build/equivalence.json"
```

两份 CCTP 证明在五种配置各复放一次。另有 25 笔标量边界花费。两引擎接受全部 35 笔，且 BSV Node 将它们入块。CCTP 的 28 个负例均被双引擎拒绝，包括互换公开输入、换成匹配的 MSM 见证后仍保留原证明、篡改动态斜率和篡改固定线表。独立的 CCTP 宿主最终幂也接受两份原证明并拒绝两次互换。显式上界回归用在较宽策略下通过的同一份证明见证，核验较窄锁对其拒绝。[上界回归](tests/test_forth_verifier.py)
