# P2PKH-Schnorr 付款协议

[English](spec.en.md) · [项目首页](../README.zh-CN.md)

所有者字段是 32 字节 BIP340 x-only 公钥的 HASH160。其余脚本字节固定。创建收款输出时按布局清单填入所有者字段。识别输出时先比对脚本长度和全部固定字节，再读取所有者哈希。[固定模板](../versions/v0.6.0/template.hex) · [布局清单](../versions/v0.6.0/layout.json)

钱包按所选 sighash 为当前输入构造 BSV 签名预映像。外部签名器收到其 SHA256d 作为 32 字节 BIP340 消息，返回标准签名字节。锁验证 Schnorr 签名，并通过 PUSHTX 将同一消息绑定到当前输入。钱包默认用 BIP143 ALL。使用 OTDA 时应从可信链视图取得 Chronicle 激活状态，使用 SINGLE 时要提供同索引输出。[Forth 合约](../reference/schnorr.fth)

| 解锁栈项 | 编码 |
| --- | --- |
| 签名预映像 | 按所选 BSV sighash 规则和本模板的 scriptCode 构造 |
| 打包见证 | 公钥 x（32 字节）、偶数公钥 y（32 字节）、BIP340 签名（64 字节）、偶数签名点 y（32 字节） |
| 模式选择值 | 普通付款路径为 Script 数值 0 |

签名完成后，钱包根据公开数据推导两个额外的 y 坐标，按无符号大端域元素编码。脚本检查坐标范围、偶数条件和公钥点曲线方程，计算包含 r、公钥 x 和消息的标签哈希挑战。脚本求 sG − eP，排除无穷远点，再用域上的同余关系与有限偶数签名点比对两个射影坐标。这样可以在脚本内验证坐标，无需执行开方或求逆。[BIP340 验签](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [完备点加公式](https://eprint.iacr.org/2015/1060)

独立验签器接收消息、公钥 x、公钥 y、签名和签名点 y，供合规向量测试使用。锁定 UTXO 时使用固定付款模板。仓库中的 CSV 来自下列固定提交。[官方测试向量](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv)

<a name="compact-doubling"></a>

## 专用倍点公式

累加点使用齐次坐标，满足域方程 `X³ = Y²Z − 7Z³`。将相同的点代入完备点加公式，交叉项为 `2XY`、`2XZ` 和 `2YZ`。再代入曲线方程即可得到以下倍点坐标。[Forth 实现](../../../src/fourthgraph/stdlib/secp256k1.fth)

- 令 `a = Y²`、`t = 21Z²`、`q = 3t`。
- 在有限域内计算 `X' = 2XY(a − q)`、`Y' = a(a + 2q) − q*t`、`Z' = 8Y³Z`。

无穷远点 `(0:Y:0)` 的 `Y` 非零，倍点结果为 `(0:Y⁴:0)`。

## 联合标量乘法

令 `k = n − e`、`B = 2^128`。锁将 `s` 拆成 `s0 + B*s1`，使用固定基点 `H = B*G`。secp256k1 自同态 `φ(x,y) = (βx,y)` 满足 `φ(P) = λP`。锁将 `k` 分解成有符号的 `k1` 和 `k2`，满足 `k ≡ k1 + λ*k2 (mod n)`。四个标量分量的绝对值均可用 128 位表示。[窗口实现](../../../src/fourthgraph/stdlib/bip340.fth) · [secp256k1 格基](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h#L78-L135)

格基满足 `ai + bi*λ ≡ 0 (mod n)`，行列式为 `n`。锁用精确整数除法计算 `c1 = round(k*b2/n)` 和 `c2 = round(-k*b1/n)`，再从 `(k, 0)` 减去两项格基倍数，得到有符号的 `(k1, k2)`。每个分量的误差上界为对应两项格基坐标绝对值之和的一半，锁也检查两个分量的绝对值小于 `B`。当 `e = 0` 时，`k = n` 的两个分量均为零。[标量分解](../../../src/fourthgraph/stdlib/secp256k1.fth)

验签器用 64 个两位窗口计算 `s0*G + s1*H + k1*P + k2*φ(P)`。固定的 `G,H` 使用仿射点表，`P,φ(P)` 按分量符号选点后生成射影点表。每窗对两张表分别按 `4*高位数字 + 低位数字` 查表累加。从第二窗开始，查表前先对累加点倍点两次。初始累加点为无穷远点。索引为零时跳过该次点加。固定点表使用右侧 `Z = 1` 的专用完备点加。查表数据来自公共常数和已校验的公钥，验签器仍使用原有的五个见证字段。[仿射点加](../../../src/fourthgraph/stdlib/secp256k1.fth)
