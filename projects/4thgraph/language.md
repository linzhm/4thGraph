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
gate: <step> <input> <word> <signer-role>
split-authority: <signer-role>
recovery: <block-height> <signer-role>
independent-submit <gate-or-work-step>
```

- `bsv-effect:` 为随后同名的冒号定义声明静态栈效果。输入和输出的顺序均从栈底写到栈顶。
- `work:` 声明外部数据名、计算词和分支签名角色。计算词必须具有 `u32 -- u32` 效果，并能编译成 Script。
- `join:` 按顺序消费两个不同的工作步骤。汇合词具有 `u32 u32 -- route` 效果。声明次序决定结果的逻辑次序，以及拆分的工作输出索引与汇合的输入次序。
- `gate:` 可选。其词具有 `u32 -- cell` 效果，只有非零结果允许继续。完整融合先验证条件，再运行分支和汇合。拆分时，如果门和拆分的授权角色相同、数据和签名可同时取得且没有独立边界，则同一笔交易执行两步。独立门只创建已承诺的拆分锁，拆分随后绑定 `gate-step:0`。同一规则适用于两个版本的交易。
- `split-authority:` 指定创建工作输出的签名角色。拆分完成后，每支只需对应的签名角色即可提交。
- `recovery:` 给部署、独立门、工作和结果的可花费输出增加超时退款分支。指定的十进制区块高度须在 1 到 499,999,999 之间。锁验证实际交易的 `nLockTime` 等于该值、输入序列为 `0xfffffffe`，并要求指定角色签署。每笔退款只花费一个实际中间 outpoint，发送至该角色的 P2PK，价值为原输出扣除固定 1,000 sat 费用。`nLockTime = h` 的退款最早可进入高度 `h+1` 的区块。常规路径和退款路径花费同一 UTXO。
- 同一程序中，重复的外部输入名表示同一个 `u32` 值。例如 `work: a x double alice` 和 `work: b x inc bob` 都读取 `x`。融合时见证传一次 `x`，锁将其复制到各使用位置。拆分时，`split` 在每个使用 `x` 的工作锁开头写入相同的值，并核对整个输出向量。若独立的门也读取 `x`，门先将其写入拆分锁，再由拆分传给工作锁。运行器从实际花费的前输出读取该值。各分支仍可独立提交。
- `independent-submit` 将工作步骤声明为可独立提交的交易边界。存在该约束时，自动调度选择拆分，强制融合报告源码行号。编译器也接受原型曾使用的后缀写法 `<work-step> independent-submit`。

宿主词使用独立类型。 `bsv-lookup-utxo ( outpoint -- utxo )` 由 UTXO 提供者执行，`bsv-sign ( request -- bytes )` 由外部签名器返回 DER 签名，`bsv-submit ( transaction -- bytes )` 由提交接口执行。 `utxo>outpoint` 和 `utxo>script` 读取已绑定输出。词库描述各自的验证依据，宿主词进入工作词或汇合词的调用链时，构建会报告调用位置和对应的宿主词。

## 构建接口

构建 JSON 通过 `schema_version` 标识格式，记录编译器版本、目标交易版本集合、优化规则、符号输入、被每笔交易执行的源码步骤和脚本字节。`source_sha256` 为源文件原始字节的 SHA-256。核对 `artifact_sha256` 时移除该字段，按键排序，保留数组顺序，将非 ASCII 字符写为 JSON 转义并移除分隔符两侧的空白，再对这些 UTF-8 字节计算 SHA-256。构建结果可在签名前复现，真实父交易和签名仍由实例化阶段绑定。

`--explain` 报告候选的约束、选择和每笔交易的符号父输出。成本估算使用报告中列出的固定见证长度和数据样本。自动选择先排除不符合约束的候选，再依次按整条路径字节、单笔最大签名验证次数和依赖深度排序。完全同分时优先融合。可用性说明本次能同时取得的数据和角色，交易模板逐步列出各自仍需提供的输入与签名。

每个合格候选的 `artifact_sha256` 是同一配置下普通构建 JSON 的摘要。包含 `schedule_explanation` 的 JSON 对整份文档另算自己的 `artifact_sha256`。复放格式 2 保留普通构建 JSON，按源码、候选构建摘要和路由标注每条路径。离线报告并列显示静态候选资格和复放状态，并核对实际交易图及终端输出。复放中的耗时只用于报告。固定的证据输入生成可重复的报告，新的 regtest 运行会记录新的交易和采样。 [报告生成命令](README.md#编译决策报告)

共用外部输入的计划使用 `schema_version` 2。`shared_input` 给出输入名，每个交易模板的 `external_inputs` 按见证从栈底到栈顶的顺序列出该步需要提供的值。动态输出中的 `prefix_u32_input` 指定前缀的数据来源。锁脚本依次拼接压栈操作码 `05`、四字节小端无符号值、符号字节 `00` 和 `script_suffix_hex`。只使用独立输入名的计划沿用格式 1。

`--join-witness shared` 每个汇合输入只放一次两笔结果交易共用的锁脚本后缀。Script 先按原顺序拼回两笔完整交易，再核对两者实际 outpoint、同一拆分来源和后继输出。`full` 使用原始见证布局。

`--search` 枚举已支持的交易形状。拆分候选先核对每个工作输入对应的拆分槽位，以及汇合消耗的两个有序结果输出。门与拆分合并要求同一授权角色和同时可用的门输入、签名及允许融合的源码约束。门单独提交仍须在自身交易中验证条件与签名，拆分随后绑定该输出。独立提交的工作步骤保留自己的交易。

`path-bytes` 依次比较整路字节、最大单笔签名检查次数和依赖深度。`peak-validation` 依次比较最大单笔签名检查次数、最大单笔输入脚本字节、整路字节和依赖深度。输入脚本字节是每笔交易各输入的解锁脚本与所花费锁脚本长度之和。两个目标同分时按候选名排序。峰值验证排序使用静态代理指标，报告另列两引擎实测耗时及每条路径的字节偏差。复放格式 3 按候选构建摘要关联两条路由，报告器也可读取既有格式 2。

`--optimize stack` 在安全降栈后分析基本块里的值和最后一次使用。它按栈深选择浅层取数指令或 `PICK`、`ROLL`，在已证明总能执行的基本块内复用相同计算。候选字节码更短时才替换原块。两个 `IF` 分支分别处理，栈输出顺序仍由 Forth 定义决定。

`stack-local-operand-scheduling` 在同一个基本块中尝试复用栈顶最后使用的值以及成对取栈。它只对完整字节码为一个可交换操作码的二元运算比较两个操作数顺序。记录的 `basis` 给出总性、剩余引用数和输出顺序条件，`script_bytes` 给出改写前后的字节数。

`--optimize baseline` 使用原有字节码后端。`--optimize safe` 在带类型的栈表示上做范围分析和分支指令选择。输出的 `rewrites` 记录规则、源码行列及触发规则的栈类型和范围。单独导出的词遵循 `takes` 中的数值范围，交易模板在进入计算前检查外部输入范围。

`--capabilities` 输出机器可读的词集、执行位置和交易版本清单。 `--entry <word>` 只编译指定的已标注定义，便于检查 Script 字节和栈签名。事务构建在发现首个无效使用时退出，并指明源文件行列。诊断区分未知词、未导入的 Core Extension 词、无法下沉的标准词和调用链中的宿主词。

```sh
PYTHONPATH=. python projects/4thgraph/protocol.py --capabilities
PYTHONPATH=. python projects/4thgraph/protocol.py projects/4thgraph/example.fth --entry inc
```

版本目标与词集、运算语义和调度分别配置。 `--target both` 让同一份锁接受版本 1 和 2，选 `Contracts.prepare(..., version=1)` 或 `version=2` 在实例化每步时决定实际版本。锁验证当前交易和每份结果父交易自身的版本及来源。版本进入签名摘要，改动父交易版本后须重新绑定其后继。
