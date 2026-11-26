# 与 sCrypt Schnorr 验签器对照

[English](scrypt-comparison.en.md) · [项目首页](../README.zh-CN.md)

2021 年文章介绍的是由见证数据辅助点乘的做法。归档合约调用三次 `isMul`。每组链下点乘辅助数据声明了 512 个点和 510 个斜率，三组共 4,602 个整数字段，此外还有其他参数。配套文章提到的约 400 字节是校验一次点加的开销。以上数字来自归档源码与原文。[Schnorr 原文](https://scryptplatform.medium.com/schnorr-signatures-on-bitcoin-397ca51d8bda) · [归档合约](https://github.com/sCrypt-Inc/boilerplate/blob/2284e11c9aa22faccd266d85a992e8a91a5b70f3/contracts/schnorr.scrypt) · [归档点运算实现](https://github.com/sCrypt-Inc/boilerplate/blob/2284e11c9aa22faccd266d85a992e8a91a5b70f3/contracts/ec.scrypt) · [点运算文章](https://scryptplatform.medium.com/efficient-elliptic-curve-point-addition-and-multiplication-in-scrypt-script-f7e143a752e2)

原文的源码链接目前指向 `legacy` 分支。本次固定的提交在脚本内通过仿射点运算和求模逆来检查 `sG = R + eP`，分别计算固定基点和可变基点的点乘。挑战值为无标签的 `SHA256(r || P || m)` 对群阶取模，其中 `P` 是 65 字节的 SEC1 非压缩公钥。见证提供 `R` 的横纵坐标。[固定版本合约](https://github.com/sCrypt-Inc/boilerplate/blob/7b2cd79d005b2fcdc3c992d039efd619fb47abf7/contracts/schnorr.scrypt) · [点运算实现](https://github.com/sCrypt-Inc/boilerplate/blob/7b2cd79d005b2fcdc3c992d039efd619fb47abf7/contracts/ec.scrypt#L80-L153)

Script Lab 使用 BIP340 带标签的挑战哈希和 32 字节的公钥横坐标。脚本检查两个纵坐标见证对应的点是否在曲线上，以及纵坐标的奇偶性。`sG − eP` 采用两位窗口联合点乘，两项共用倍点步骤。计算使用齐次射影坐标，最后与 `R` 比较时也无需求模逆。[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [脚本生成器](../reference/schnorr_script.py)

## 独立验签器复放

两边沿用 BIP340 官方向量第 0 条的 32 字节消息与公钥横坐标，各自使用本身的签名格式。夹具构造单输入交易并显式提供上一输出。三份构建产物均通过 BSV Node 1.2.3 在仓库放宽脚本限制配置下的 `verifyscript`，以及固定版本的 chain-gang 验证。表内统计序列化脚本字节，包含压入见证所用的操作码。`scryptlib` 2.1.36 自带解释器以默认标志执行 `legacy` 默认构建产物时，返回 `SCRIPT_ERR_SCRIPT_SIZE`。[BIP340 向量](../template/bip340-vectors.csv) · [复放程序](../reference/compare_scrypt.py) · [隔离 regtest 配置](../../../shared/verify_node.sh)

| 验签器 | 锁定脚本字节 | 见证脚本字节 | 脚本合计字节 | chain-gang 中位耗时 | BSV Node RPC 中位耗时 |
| --- | ---: | ---: | ---: | ---: | ---: |
| sCrypt `legacy` 默认构建 | 2,248,962 | 231 | 2,249,193 | 195.2 ms | 731.3 ms |
| sCrypt `legacy`，`scryptc --asm -O` | 2,178,125 | 231 | 2,178,356 | 200.5 ms | 699.7 ms |
| Script Lab BIP340 | 29,415 | 197 | 29,612 | 3.1 ms | 13.2 ms |

耗时在 Intel Xeon Platinum 8370C Linux 主机上测得。每套引擎先预热一次，再取 15 次复放的中位数。耗时包含输入准备和验证，BSV Node 的数据还包含本机 RPC 开销。

这个夹具下，Script Lab 的脚本总尺寸比优化后的 `legacy` 版本小 **98.6%**。两种验签器各自使用自己的签名格式。30,398 字节的 P2PKH-Schnorr 付款锁还检查所有者，并将预映像绑定到当前输入。[付款实测](../README.zh-CN.md#交易实测) · [付款协议](spec.zh-CN.md)

## 编译器优化与字节下界

固定版本的 sCrypt 编译器在输出 ASM 时应用 `-O`。夹具将优化后的 ASM 汇编成脚本，再用原始见证复放。夹具也会核对默认 ASM 汇编后与默认十六进制产物逐字节相同。开启优化后，锁定脚本减少 70,837 字节，约 **3.15%**。

两种 sCrypt 构建产物都有 769 段互不重叠的 `modInverseBranchlessP` 指令，每段从操作码边界开始，占 2,544 字节，合计 **1,956,336 字节**，约为优化后锁定脚本的 89.8%。只要编译产物保留这 769 段指令及其编码，即使其余脚本全部消除，锁定脚本也至少有 1,956,336 字节。[固定版本的求逆实现](https://github.com/sCrypt-Inc/boilerplate/blob/7b2cd79d005b2fcdc3c992d039efd619fb47abf7/contracts/ec.scrypt#L61-L66) · [字节统计实现](../reference/comparison/scrypt_legacy.cjs)

即使允许改写求逆例程，只要仍保留 769 个互不重叠的内联求逆，要把总大小压到 Script Lab 的 29,415 字节以内，每段求逆的平均预算也不到 39 字节，还未计入其他指令。把联合射影点乘移植到 sCrypt 后，这个下界的前提就消失了。

## 同见证格式的 BIP340 对照

两种实现使用 BIP340 带标签的挑战哈希、x-only 公钥规则和相同的五个见证字段。高级 sCrypt 版采用单比特联合点乘和完备齐次坐标点加，Script Lab 使用自同态分解和 64 个两位窗口。复放程序给两份 sCrypt 产物补上相同的三字节栈深度检查。[sCrypt 源码](../reference/comparison/bip340.scrypt) · [对照程序](../reference/compare_bip340.py)

| BIP340 验签器 | 锁定脚本字节 | 见证字节 | 栈载荷峰值 | chain-gang 中位耗时 | BSV Node RPC 中位耗时 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 高级 sCrypt 默认构建 | 131,479 | 197 | 2,235 B | 9.0 ms | 53.0 ms |
| 高级 sCrypt `--asm -O` | 122,710 | 197 | 2,235 B | 8.7 ms | 56.2 ms |
| Script Lab | 29,415 | 197 | 3,290 B | 3.2 ms | 13.0 ms |

三份产物在两套引擎上均接受 9 条有效 BIP340 向量，拒绝 10 条无效 BIP340 向量和 8 条错误见证。本地测试还逐字节复算了 8 条附有私钥的官方签名。栈载荷取官方第 0 条向量在开发求值器中的主栈与备用栈数据总量峰值。耗时在同一主机预热一次后取 15 次复放的中位数。

这个夹具中，Forth 验签器比优化后的 sCrypt 版少 93,295 字节，窗口表增加了栈载荷峰值。完整付款和双方签名成本见另一份实测。[MuSig2 和原生 CHECKMULTISIG](threshold-comparison.zh-CN.md)

## 复现

按[项目验收说明](../README.zh-CN.md#复现验收)准备 Python 环境，然后在仓库根目录运行。本次使用 Node.js 22 运行复放程序。编译器和 BSV Node 使用 Linux x86-64 发行包。复放程序校验上游源码提交和编译器的 SHA-256。

```sh
scratch=$(mktemp -d)
git clone --no-checkout https://github.com/sCrypt-Inc/boilerplate.git "$scratch/boilerplate"
git -C "$scratch/boilerplate" checkout --detach 7b2cd79d005b2fcdc3c992d039efd619fb47abf7
npm --prefix "$scratch/boilerplate" ci --ignore-scripts --no-audit --no-fund
gh release download v1.19.1 --repo sCrypt-Inc/compiler_dist \
  --pattern 'scryptc-1.19.1-Linux-x86_64' --dir "$scratch"
chmod +x "$scratch/scryptc-1.19.1-Linux-x86_64"
export SCRYPTC="$scratch/scryptc-1.19.1-Linux-x86_64" GHCRTS=-N2
PYTHONPATH=. bash shared/verify_node.sh -- \
  .venv/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_scrypt.py \
  "$scratch/boilerplate" --compiler-study --samples 15
PYTHONPATH=. bash shared/verify_node.sh -- \
  .venv/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_bip340.py \
  --compiler "$SCRYPTC" --samples 15
```
