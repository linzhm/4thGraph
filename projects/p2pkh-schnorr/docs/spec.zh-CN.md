# P2PKH-Schnorr 付款协议

[English](spec.en.md) · [项目首页](../README.zh-CN.md)

所有者字段是 32 字节 BIP340 x-only 公钥的 HASH160。其余脚本字节固定。创建收款输出时按布局清单填入所有者字段。识别输出时先比对脚本长度和全部固定字节，再读取所有者哈希。[固定模板](../template/template.hex) · [布局清单](../template/layout.json)

钱包按所选 sighash 为当前输入构造 BSV 签名预映像。外部签名器收到其 SHA256d 作为 32 字节 BIP340 消息，返回标准签名字节。锁验证 Schnorr 签名，并通过共用的 PUSHTX 将同一消息绑定到当前输入。钱包默认用 ForkID ALL。使用 OTDA 时应从可信链视图取得 Chronicle 激活状态，使用 SINGLE 时要提供同索引输出。[交易绑定实现](../../../shared/pushtx.py)

| 解锁栈项 | 编码 |
| --- | --- |
| 签名预映像 | 按所选 BSV sighash 规则和本模板的 scriptCode 构造 |
| 打包见证 | 公钥 x（32 字节）、偶数公钥 y（32 字节）、BIP340 签名（64 字节）、偶数签名点 y（32 字节） |
| 模式选择值 | 普通付款路径为 Script 数值 0 |

签名完成后，钱包根据公开数据推导两个额外的 y 坐标，按无符号大端域元素编码。脚本检查坐标范围、偶数条件和公钥点曲线方程，计算包含 r、公钥 x 和消息的标签哈希挑战。脚本求 sG − eP，排除无穷远点，再用域上的同余关系与有限偶数签名点比对两个射影坐标。这样可以在脚本内验证坐标，无需执行开方或求逆。[BIP340 验签](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [完备点加公式](https://eprint.iacr.org/2015/1060)

独立验签器接收消息、公钥 x、公钥 y、签名和签名点 y，供合规向量测试使用。锁定 UTXO 时使用固定付款模板。仓库中的 CSV 来自下列固定提交。[官方测试向量](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv)
