# P2PKH-Schnorr 付款协议

[English](spec.en.md) · [项目首页](../README.zh-CN.md) · [钱包 SDK](sdk.zh-CN.md#quickstart)

## 锁定与花费

收款输出承诺 32 字节 BIP340 x-only 公钥的 HASH160。按所选发布模板填写所有者字段。钱包比对脚本长度和全部固定字节来识别版本。v0.6.0 至 v0.17.0 的发布模板使用相同的输入绑定 `scriptCode` 片段和解锁后栈布局。[当前模板与所有者字段](../versions/v0.17.0/layout.json) · [版本目录](../versions/index.json)

| 阶段 | 角色与校验条件 |
| --- | --- |
| 入金 | 付款方创建包含 Schnorr 锁和金额的交易输出。收款钱包核验上一输出位置、金额、模板和所有者。 |
| 授权 | 钱包按已审批的 sighash 构造当前输入的签名预映像。外部签名器将其 SHA256d 作为 32 字节 BIP340 消息，返回 64 字节签名。 |
| 组装 | 钱包核验签名，从公开数据推导两个纵坐标，再生成输入解锁脚本。纵坐标按无符号大端域元素编码。 |
| 验证 | Script 校验所有者哈希和 BIP340 等式。PUSHTX 通过原生 `OP_CHECKSIG` 把已验证消息绑定到实际输入。节点根据上一输出和链上下文验证花费。 |

[付款 Forth](../forth/schnorr.fth) · [钱包签名流程](../reference/payment.py) · [授权输入](../../../src/fourthgraph/bsv/spend_authorization.py)

<a name="unlock-stack-and-sighash"></a>

## 解锁栈与 sighash

按输入脚本执行后的栈底到栈顶读取。

| 栈项 | 编码 |
| --- | --- |
| 签名预映像 | 普通路径或配套路径所需的完整 BSV 预映像。 |
| 打包见证 | 按顺序拼接公钥 x（32 B）、偶数公钥 y（32 B）、BIP340 `r \|\| s`（64 B）和偶数 nonce y（32 B）。 |
| 模式选择值 | 普通路径为 Script 数值 0，缺少同索引输出的 OTDA SINGLE 配套路径为 1。 |

钱包默认使用 BIP143 ALL（`0x41`）。ALL、NONE 和 SINGLE 的输出承诺按所选 BSV sighash 规则执行，ANYONECANPAY 改变输入承诺范围。SDK 请求 OTDA 时需要可信的 Chronicle 激活上下文，请求 SINGLE 时需要同索引输出。锁还实现了单独验收的无配对 OTDA SINGLE 路径。该路径将 Schnorr 消息绑定到 `hashOutputs` 为零的 BIP143 SINGLE 预映像，并检查对应的原生 OTDA SINGLE 条件。常规钱包调用要求提供同索引输出。[绑定与 sighash 检查](../forth/schnorr.fth) · [验收用例](../reference/test_schnorr.py)

### OTDA 预映像编码

Chronicle 已激活时，版本 2 的 OTDA ALL 或有同索引输出的 OTDA SINGLE 可选用较短的构造程序，两者均涵盖 ANYONECANPAY 形式。组装器对相同完整预映像的有效编码按大小排序。混合模板里未识别的输出脚本保留原始字节。签名器与锁取得相同的完整预映像，交易 ID 取决于包含最终解锁脚本的完整交易序列化。[选择规则](../../../src/fourthgraph/compiler/preimage.py) · [构造器实测](high-level-forth.zh-CN.md#otda-constructor)

## BIP340 验签

Script 检查四个坐标的范围、两个纵坐标的偶性和公钥点的曲线方程，再用群阶检查签名标量。挑战使用原始 `r`、x-only 公钥和消息计算 BIP340 标签哈希。验签器计算 `sG − eP`，检查 `Z` 非零，并用域上的同余关系将两个射影坐标与有限 nonce 点比对。公开坐标见证使 Script 无需开方或求逆即可完成检查。[验签实现](../../../src/fourthgraph/stdlib/bip340.fth) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

实现把四个坐标、签名标量和挑战哈希解码为六个无符号 32 字节字段。整数转换前，五次带掩码的块交换在原位置反转各字段。独立验签入口接收消息、公钥 x、公钥 y、签名和 nonce y。付款锁以 32 字节预映像哈希作为消息。[共享解码](../../../src/fourthgraph/stdlib/script-fragments.fth) · [固定的官方向量](../versions/v0.6.0/bip340-vectors.csv)

## 坐标缩放

验签器用原始坐标检查见证并计算挑战哈希。点运算在同一个有限域内进行，取满足 `21u⁶ = 1 mod p` 的非零常数 `u`，将 `(X:Y:Z)` 映射为 `(u²X:u³Y:Z)`。这个映射将 `y² = x³ + 7` 变成 `y² = x³ + 1/3`，保持群运算并固定无穷远点。脚本缩放公钥点和签名点，固定表直接存放缩放后的生成点倍数，最终比较也在缩放后的曲线上进行。[共享曲线内核](../../../src/fourthgraph/stdlib/secp256k1.fth)

求常数时令 `t = 21⁻¹ mod p`、`m = (p−1)/3`。对 secp256k1 的域素数，`t^m = 1`，`3` 在模 `m` 下可逆，且 `p ≡ 3 mod 4`。取 `A = t^(3⁻¹ mod m) mod p` 和 `B = t^((p+1)/4) mod p`，则 `A³ = B² = t`。令 `u = B/A`，即可得到 `u² = A` 和 `u³ = B`。[缩放与独立算术测试](../../../tests/test_secp256k1_library.py)

<a name="compact-doubling"></a>

## 专用倍点公式

缩放后的累加点满足域方程 `X³ = Y²Z − Z³/3`。将相同的点代入完备点加公式，交叉项为 `2XY`、`2XZ` 和 `2YZ`。再代入曲线方程即可得到以下倍点坐标。[Forth 实现](../../../src/fourthgraph/stdlib/secp256k1.fth)

- 令 `a = Y²`、`t = Z²`、`q = 3t`。
- 在有限域内计算 `X' = 2XY(a − q)`、`Y' = a(a + 2q) − q*t`、`Z' = 8Y³Z`。

无穷远点 `(0:Y:0)` 的 `Y` 非零，倍点结果为 `(0:Y⁴:0)`。

每个窗口的连续两次倍点中，第一次的 `Y'`、`Z'` 立即取模。第二次倍点里的 `Y''`、`Z''` 只依赖这两个坐标，`X''` 对 `X'` 是线性的，因此可将 `X'` 的取模推迟到求出 `X''` 之后。在缩放曲线上，每次倍点对 X 的乘因子绝对值小于 `6p³`。输入坐标已取模时，两次倍点的未取模 X 绝对值小于 `36p⁷`，ScriptNum 最多占 225 字节。

## 联合标量乘法

令 `k = n − e`、`B = 2^128`。锁将 `s` 拆成 `s0 + B*s1`，使用固定基点 `H = B*G`。secp256k1 自同态 `φ(x,y) = (βx,y)` 满足 `φ(P) = λP`。锁将 `k` 分解成有符号的 `k1` 和 `k2`，满足 `k ≡ k1 + λ*k2 (mod n)`。四个标量分量的绝对值均可用 128 位表示。[窗口实现](../../../src/fourthgraph/stdlib/bip340.fth) · [secp256k1 格基](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h#L78-L135)

令 `A = a1 = b2`、`D = −b1`。格基为 `(A, −D)` 和 `(A+D, A)`，满足 `A² + AD + D² = n` 和 `ai + bi*λ ≡ 0 mod n`。锁复用挑战取模所用的群阶，计算 `c1 = floor((kA + floor(n/2))/n)` 和 `c2 = floor((kD + floor(n/2))/n)`。结果为 `k1 = k − A(c1+c2) − Dc2` 和 `k2 = Dc1 − Ac2`。[标量分解](../../../src/fourthgraph/stdlib/secp256k1.fth)

舍入误差 `ε1 = kA/n − c1` 和 `ε2 = kD/n − c2` 的绝对值均不超过二分之一。由行列式恒等式可得 `k1 = Aε1 + (A+D)ε2` 和 `k2 = −Dε1 + Aε2`，绝对值的上界分别为 `(2A+D)/2` 和 `(A+D)/2`，均小于 `2^128`。该上界覆盖 `0 ≤ k ≤ n` 的整个区间。`k = n` 时两个分量均为零。[舍入测试](../../../tests/test_secp256k1_library.py)

验签器用 64 个两位窗口计算 `s0*G + s1*H + k1*P + k2*φ(P)` 的缩放像。固定仿射表存放 `G,H` 组合的缩放像。变量表用缩放后的 `P,φ(P)`，按分量符号选点后生成。构建变量表时，每行依次加上缩放后的仿射点 P。每窗对两张表分别按 `4*高位数字 + 低位数字` 查表累加。累加点从无穷远点开始。v0.17.0 按 `O + P = P` 将首窗选中的变基射影点直接载入累加器。变基索引为零时保留无穷远点。随后，固定表索引非零就执行完备仿射点加。之后 63 窗在每次查表累加前先倍点两次，索引为零时跳过对应的点加。构建变量表和累加固定点时都使用右侧 `Z = 1` 的专用完备点加。[仿射点加](../../../src/fourthgraph/stdlib/secp256k1.fth)

验签器将四个 128 位分量打包成一个 64 字节值。在 `(s0, s1, |k1|, |k2|)` 中，编号为 `ℓ` 的分量从最低位起的第 `d = 4q + r` 个两位数字，在小端编码拼接后位于第 `j = 64ℓ + 4(15 − q) + r` 个两位位置。六次带掩码的交换实现置换 `rotl8(j, 2) XOR 0xf0 = 4d + ℓ`，同时调整字节顺序。结果每字节的低四位是固定表索引，高四位是变量表索引。[索引打包](../../../src/fourthgraph/stdlib/bip340.fth)

验签器在迭代前批量计算栈深度。v0.14.0 将每个打包字节扩为变量索引和固定索引两个字节，把 64 对深度存入一条流。令 `m` 表示索引 `i` 是否非零，两个深度都先算 `3m + 2i`，再给变量表字节加上 `79m − 5i`，得到 `82m − 3i`。索引为零时深度也为零，运算不会跨字节进位或借位。每窗先切下两个字节，再拆开两个深度。[深度计算](../../../src/fourthgraph/stdlib/bip340.fth)

v0.12.0 直接使用这些深度字节。零字节在点加分支中判为假，非零字节已经是最短的正数 ScriptNum。构建变量点表时，令 `ε` 为两个变量基点的相对符号，则 `Q = εφ(P)`。验签器把 `2P` 和 `3P` 的 X 坐标乘以 β 后取模，把 Y 坐标乘以 ε，保留 Z 坐标，得到 `2Q` 和 `3Q`。[点表构造](../../../src/fourthgraph/stdlib/bip340.fth)

构建点表后，验签器将域素数放到累加点正下方。倍点和点加的操作数都在素数上方，因此编译时可以确定每次坐标取模所用的栈深度。固定基点表按索引降序压栈。以最上方的累加点坐标为深度零，索引 `i > 0` 的横坐标位于深度 `2i + 3`。[窗口循环](../../../src/fourthgraph/stdlib/bip340.fth) · [点运算](../../../src/fourthgraph/stdlib/secp256k1.fth)
