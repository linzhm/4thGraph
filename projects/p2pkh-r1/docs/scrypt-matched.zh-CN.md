# P2PKH-R1 与 sCrypt 同算法对照

[English](scrypt-matched.en.md) · [项目首页](../README.zh-CN.md) · [公开实现的历史对照](scrypt-comparison.md)

旧对照的公开 `scrypt-ts-lib` R1 单入口验签器为 **2,248,716 字节**。它使用仿射点运算、分开点乘及内联模逆 ASM。八入口测试合约为 4,485,650 字节。那一轮用公开付款向量复放了两个独立验签器和当时的付款锁。数字适用于指定的构建与验收口径。[上游 R1 源码](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/src/ec/secp256r1.ts) · [上游 ASM 覆盖](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/.asm/asm.json)

## 在同一个付款模板里更换算术内核

Script Lab v0.2.0 基线直接使用现有钱包签名入口和固定模板。对照组将同样的 P-256 射影点加、`a = −3` 专用倍点和有符号余数规则写成高级 sCrypt，用 `scryptc 1.20.0 --asm -O` 编译。夹具提取算术字节码，加入读取栈上域常量的适配指令，再接入相同的四位窗口、交易绑定和见证布局。sCrypt 内核尺寸包含适配指令。两版分别使用从各自内核生成的 OTDA 重建程序。[高级 sCrypt 内核](../reference/comparison/projective.scrypt) · [编译提取和交易复放](../reference/compare_scrypt.py)

| 项目 | Script Lab v0.2.0 | sCrypt `-O` 算术内核 |
| --- | ---: | ---: |
| 点加，锁中静态展开 135 次 | 147 B | 215 B |
| 倍点，锁中静态展开 263 次 | 76 B | 117 B |
| 完整付款锁 | **46,302 B** | **66,265 B** |
| OTDA 重建程序 | 3,913 B | 4,022 B |

夹具在组装时标记点加和倍点的展开位置，然后逐字节验证两份完整锁都从相同的外层脚本展开。两版内核外的 6,469 字节相同。锁的 **19,963 字节**差额来自两类内核，即 `135 × 68 + 263 × 41`。当前 Script Lab 生成器按最后一次使用消耗栈上的值，重排独立表达式，并共享域常量。这组数字对应两个具体的算术实现及其栈上接入方式。[Script Lab 算术生成器](../reference/curve_compiler.py)

## 实测交易和验收

2×2 场景创建两个各自版本的 R1 输出。边际通过 3×2 和 2×3 实测。直接退出从一笔普通 P2PKH 入金开始，花费到普通 P2PKH。一次周转在中间插入一笔 2×2 R1 转账。金额和脚本字节数由同一套基准程序生成。

| 模式 | 实现 | 每输入解锁 | 2×2 交易 | 新增输入 | 新增输出 | 入金后退出 | 含一次周转 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL | Script Lab | 326 | 93,374 | 369 | 46,313 | 93,599 | 186,974 |
| BIP143 ALL | sCrypt 内核 | 326 | 133,304 | 369 | 66,278 | 133,530 | 266,833 |
| OTDA ALL | Script Lab | 4,264 | 101,250 | 4,430 | 46,393 | 93,613 | 194,863 |
| OTDA ALL | sCrypt 内核 | 4,377 | 141,406 | 4,543 | 66,362 | 133,544 | 274,949 |

单位均为字节。sCrypt 内核使锁超过 65,535 字节，输出的 CompactSize 长度字段从 3 字节变成 5 字节。OTDA 复用重建程序，所以每输入只多 113 字节。栈载荷峰值在 BIP143 为 3,474 / 4,216 字节，在 OTDA 为 185,613 / 265,473 字节，顺序均为 Script Lab / sCrypt 内核。数值为开发求值器测得的首输入主栈与备用栈数据量。[统一计量口径](../../../docs/benchmark.zh-CN.md)

两进两出的验证耗时也按 Script Lab / sCrypt 内核排序。BIP143 在 chain-gang 为 10.4 / 11.0 ms，在 BSV Node 本机 RPC 为 41.4 / 47.2 ms。OTDA 对应为 10.1 / 11.4 ms 和 42.0 / 50.0 ms。数据来自同一台 AMD EPYC 9V74 Linux 主机，每组预热一次，再取 15 次中位数，包含输入准备与验证。

算术差分覆盖 450 组坐标边界和确定性样本。两版分别复放 96 笔付款用例，覆盖交易版本 1 和 2、全部 12 种配对 sighash、未配对 SINGLE，以及锁定时间与输出金额变更。夹具也执行每版有效用例的 64 份见证，逐字节核对签名原像，并确认实际采用 50 份字面原像、10 份重建原像与 4 份伴随路径见证。BSV Node 1.2.3 在 Chronicle 已激活且上一输出创建于激活之后的 `verifyscript` 上下文逐输入核验，固定版本 chain-gang 核对整笔交易结果。[验收入口](../reference/compare_scrypt.py)

另用未放宽脚本和交易大小策略的隔离 regtest 复放真实 UTXO。两版在 BIP143 ALL 和 OTDA ALL 下的入金与直接退出共 8 笔交易，均进入内存池并出块。sCrypt 内核版的两笔入金各约 133 KB。上表的周转字节数来自 `verifyscript` 测量。 [入金与出块夹具](../../../src/fourthgraph/benchmark/admission.py) · [节点启动参数](../../../tools/verify_node.sh)

公开版最直接的体积改进是把点乘循环换为射影运算和窗口点乘，并把唯一的 ECDSA 标量逆元作为见证交给脚本核验。若要进一步压缩这份 sCrypt 候选，应缩短重复次数最多的倍点内核，并复用点加的中间量、减少通用函数生成的栈清理。独立验签、付款绑定和 OTDA 重建各自使用上面的数据口径。

## 复现

按[开发入口](developer.zh-CN.md)配置 Python 环境，从仓库根目录运行。

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-r1/workspace/comparison-venv
projects/p2pkh-r1/workspace/comparison-venv/bin/python -m pip install \
  -r projects/p2pkh-r1/reference/requirements.txt 'ecdsa==0.19.1'
scratch=$(mktemp -d)
gh release download v1.20.0 --repo sCrypt-Inc/compiler_dist \
  --pattern 'scryptc-1.20.0-Linux-x86_64' --dir "$scratch"
chmod +x "$scratch/scryptc-1.20.0-Linux-x86_64"
GHCRTS=-N2 PYTHONPATH=src:. bash tools/verify_node.sh -- \
  projects/p2pkh-r1/workspace/comparison-venv/bin/python projects/p2pkh-r1/reference/compare_scrypt.py \
  --compiler "$scratch/scryptc-1.20.0-Linux-x86_64" --output projects/p2pkh-r1/workspace/build/scrypt-comparison.json
GHCRTS=-N2 PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- \
  projects/p2pkh-r1/workspace/comparison-venv/bin/python projects/p2pkh-r1/reference/compare_scrypt.py \
  --compiler "$scratch/scryptc-1.20.0-Linux-x86_64" --admission \
  --output projects/p2pkh-r1/workspace/build/scrypt-admission.json
```
