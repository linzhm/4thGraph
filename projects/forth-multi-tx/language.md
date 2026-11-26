# Forth 语义与 BSV 扩展规范

## 兼容范围

编译器以 Forth 2012 Core 为语义基线，实现适合静态栈检查和 BSV Script 的有界子集。定义名查找不区分大小写。冒号定义用 `: … ;`，`( … )` 在源文件中只作注释。构建前为定义显式声明 `bsv-effect:`，编译器检查该定义实际留下的栈。支持 `IF … [ELSE …] THEN`，并要求两条分支在汇合处具有相同栈类型。编译时已读到的定义可被后续定义调用。 [Forth 2012 Core](https://forth-standard.org/standard/core)

- 本实现把 `cell` 定为 64 位二进制补码。Script 中用等价的有符号 ScriptNum 表示。标准 `+`、`-` 等 cell 算术超出范围时按模 2⁶⁴ 回绕。带符号比较与 `U<` 的无符号比较读取同一位模式。比较得到的 Forth flag 为全 1 或全 0，对应 `-1` 或 `0`。 `IF` 接受任何非零 cell 为真。
- 数字字面值属于 `cell`。直接数字以十进制解释，也接受 Forth 的显式前缀 `#`、`$`、`%` 和可打印字符字面值，如 `'A'`。地址空间、运行时进制切换、I/O 和动态执行等功能目前保留为构建诊断。
- 可选词集在使用前用 `bsv-use` 声明。当前可导入 `core-ext` 的子集，含 `TRUE`、`FALSE`、`NIP`、`TUCK`、`0<>`、`0>`、`<>` 和行注释词 `\`。其它词集以及当前无法编译的 Core Extension 词有各自的错误信息。 [Forth 2012 使用要求](https://forth-standard.org/standard/usage)

## 扩展命名

保留标准词的名字和语义。BSV 扩展名称用类型或领域概念表明操作对象，例如 `u32+`、`bytes-cat`、`route-review`。转换词用 `源>目标`。源文件里的命名声明用结尾冒号，读取后续符号参数。宿主请求用 `bsv-` 前缀，让调用者能看出它将离开 Script 的执行范围。

| 词 | 栈效果 | 语义 |
| --- | --- | --- |
| `u32+` | `u32 u32 -- u32` | 加法模 2³² |
| `u32<` | `u32 u32 -- cell` | 无符号比较，返回标准 Forth flag |
| `cell>u32` | `cell -- u32` | 取低 32 位 |
| `u32>cell` | `u32 -- cell` | 零扩展，值保持在 0 至 2³²−1 |
| `bytes-hex <pairs>` | `-- bytes` | 读取一项或多项十六进制字节对，字节顺序与书写顺序一致 |
| `bytes-cat` | `bytes bytes -- bytes` | 按栈中从左到右的顺序拼接 |
| `bytes-sha256` | `bytes -- bytes` | 返回原始 32 字节 SHA-256 摘要 |
| `bytes=` | `bytes bytes -- cell` | 逐字节比较，返回标准 Forth flag |
| `route-review`、`route-settle` | `-- route` | 返回复核或结算路由。由锁验证实际后继的金额和脚本 |

`+` 接受两个 cell。 `u32+` 接受两个 `u32`。需要跨越类型边界的源码应写出转换，例如 `1 cell>u32 u32+`。

## 交易声明

顶层声明读取符号参数。各声明不接触运行时 Forth 数据栈。

```text
bsv-use <optional-wordset>
bsv-effect: <word> <input-types...> -- <output-types...> ;
work: <step> <input> <word> <signer-role>
join: <step> <left-work> <right-work> <word>
split-authority: <signer-role>
independent-submit <work-step>
```

- `bsv-effect:` 为随后同名的冒号定义声明静态栈效果。输入和输出的顺序均从栈底写到栈顶。
- `work:` 声明外部数据名、计算词和分支签名角色。计算词必须具有 `u32 -- u32` 效果，并能编译成 Script。
- `join:` 按顺序消费两个不同的工作步骤。汇合词具有 `u32 u32 -- route` 效果。声明次序决定结果的逻辑次序，以及拆分的工作输出索引与汇合的输入次序。
- `split-authority:` 指定创建工作输出的签名角色。拆分完成后，每支只需对应的签名角色即可提交。
- `independent-submit` 将工作步骤声明为可独立提交的交易边界。存在该约束时，自动调度选择拆分，强制融合报告源码行号。编译器也接受原型曾使用的后缀写法 `<work-step> independent-submit`。

宿主词使用独立类型。 `bsv-lookup-utxo ( outpoint -- utxo )` 由 UTXO 提供者执行，`bsv-sign ( request -- bytes )` 由外部签名器返回 DER 签名，`bsv-submit ( transaction -- bytes )` 由提交接口执行。 `utxo>outpoint` 和 `utxo>script` 读取已绑定输出。词库描述各自的验证依据，宿主词进入工作词或汇合词的调用链时，构建会报告调用位置和对应的宿主词。

## 构建接口

`--capabilities` 输出机器可读的词集、执行位置和交易版本清单。 `--entry <word>` 只编译指定的已标注定义，便于检查 Script 字节和栈签名。事务构建在发现首个无效使用时退出，并指明源文件行列。诊断区分未知词、未导入的 Core Extension 词、无法下沉的标准词和调用链中的宿主词。

```sh
PYTHONPATH=. python projects/forth-multi-tx/protocol.py --capabilities
PYTHONPATH=. python projects/forth-multi-tx/protocol.py projects/forth-multi-tx/example.fth --entry inc
```

版本目标与词集、运算语义和调度分别配置。 `--target both` 让同一份锁接受版本 1 和 2，选 `Contracts.prepare(..., version=1)` 或 `version=2` 在实例化每步时决定实际版本。锁验证当前交易和每份结果父交易自身的版本及来源。版本进入签名摘要，改动父交易版本后须重新绑定其后继。
