# Forth 语义与 BSV 扩展规范

[语法书](syntax.md) 给出词法、EBNF、解析时点和旧语法兼容规则。

## 兼容范围

编译器以 Forth 2012 Core 为语义基线，实现适合静态栈检查和 BSV Script 的有界子集。定义名查找不区分大小写。冒号定义用 `: … ;`。在定义名后写栈效果注释，例如 `: inc ( cell -- cell ) 1+ ;`。标准 Forth 按注释处理。4thGraph 据此检查定义的输入类型和实际留下的栈。支持 `IF … [ELSE …] THEN`，并要求两条分支在汇合处具有相同栈类型。编译时已读到的定义可被后续定义调用。 [Forth 2012 Core](https://forth-standard.org/standard/core)

- 本实现把 `cell` 定为 64 位二进制补码。Script 中用等价的有符号 ScriptNum 表示。标准 `+`、`-` 等 cell 算术超出范围时按模 2⁶⁴ 回绕。带符号比较与 `U<` 的无符号比较读取同一位模式。比较得到的 Forth flag 为全 1 或全 0，对应 `-1` 或 `0`。 `IF` 接受任何非零 cell 为真。
- 数字字面值属于 `cell`。直接数字以十进制解释，也接受 Forth 的显式前缀 `#`、`$`、`%` 和可打印字符字面值，如 `'A'`。地址空间、运行时进制切换、I/O 和动态执行等功能目前保留为构建诊断。
- 可直接使用已支持的 Core Extension 词，例如 `TRUE`、`FALSE`、`NIP`、`TUCK` 和行注释词 `\`。File-Access Extension 的 `REQUIRE` 用于构建时加载源码。编译器的词集清单列出当前支持范围。 [Forth 2012 使用要求](https://forth-standard.org/standard/usage)

## 扩展命名

保留标准词的名字和语义。BSV 扩展名称用类型或领域概念表明操作对象，例如 `u32+`、`bytes-cat`、`route-review`。转换词用 `源>目标`。顶层声明以冒号结尾并读取参数到独立的 `;`。`bsv-` 为保留命名空间，词的执行位置由接口定义。

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

## 整数范围

`range: <name> <base> <lower> <upper> ;` 声明下界包含、上界排除的整数区间。基类型可用 `cell`、`u32`、`route` 和 `script-int`。边界可用十进制或 `#`、`$`、`%` 前缀整数。声明读取数学整数。普通 Forth 字面量仍遵循 64 位 cell 语义。

```forth
range: r1-digit script-int 0 16 ;
range: r1-q-depth script-int 5 51 ;

: q-pick-depth ( r1-digit -- r1-q-depth ) 3 cell>int int* 50 cell>int swap int- ;
```

`cell>int` 保留数值并转换为 ScriptNum 类型。 `int+`、`int-`、`int*` 按 Script 整数运算，`int-rem` 保留被除数的余数符号并拒绝零除数。编译器跟踪字面量、计算结果和分支汇合的区间。调用及返回值必须满足相应签名。证明不足时报源码位置。

直接导出的词默认检查所有带范围类型的入口参数，验证规范 ScriptNum 编码和区间。已由调用方验证的入口可用 `--entry <word> --assume-input-ranges` 省去自动检查。产物 JSON 给出范围及入口检查状态。显式的 `check-range <name>` 校验栈顶值并保留它，支持在词内缩小区间，两种入口模式都执行这条检查。原始字节须先解码为相应基类型。

`--optimize safe` 和 `stack` 在证明除数为正、操作数符合数值长度约束且被除数的绝对值小于除数后省掉 `int-rem`。编译报告记录位置信息、参与证明的区间和字节差值。 [R1 窗口示例](../../projects/p2pkh-r1/experiments/forth/window-ranges.fth)

## 交易声明

交易与范围声明在源码加载时读取明确的参数，使用 `;` 结束。计算词只表达栈上的运算。

```text
range: <name> <base> <lower> <upper> ;
work: <step> <input> <word> <signer-role> ;
join: <step> <left-work> <right-work> <word> ;
gate: <step> <input> <word> <signer-role> ;
split-authority: <signer-role> ;
recovery: <block-height> <signer-role> ;
independent-submit: <step> ;
workflow-input: <value> u32 ;
stage: <stage> <word> <input-value> <output-value> <signer-role> ;
relation: <transition-word> <route-word> ;
```

- `work:` 声明外部数据名、计算词和分支签名角色。计算词必须具有 `u32 -- u32` 效果，并能编译成 Script。
- `join:` 按顺序消费两个不同的工作步骤。汇合词具有 `u32 u32 -- route` 效果。声明次序决定结果的逻辑次序，以及拆分的工作输出索引与汇合的输入次序。
- `gate:` 可选。其词具有 `u32 -- cell` 效果，只有非零结果允许继续。完整融合先验证条件，再运行分支和汇合。拆分时，如果门和拆分的授权角色相同、数据和签名可同时取得且没有独立边界，则同一笔交易执行两步。独立门只创建已承诺的拆分锁，拆分随后绑定 `gate-step:0`。同一规则适用于两个版本的交易。
- `split-authority:` 指定创建工作输出的签名角色。拆分完成后，每支只需对应的签名角色即可提交。
- `recovery:` 给各布局的部署、门、工作或状态等可花费输出增加超时退款分支。指定的十进制区块高度须在 1 到 499,999,999 之间。锁验证实际交易的 `nLockTime` 等于该值、输入序列为 `0xfffffffe`，并要求指定角色签署。每笔退款只花费一个实际 outpoint，发送至该角色的 P2PK，价值为原输出扣除固定 1,000 sat 费用。`nLockTime = h` 的退款最早可进入高度 `h+1` 的区块。常规路径和退款路径花费同一 UTXO。
- 同一程序中，重复的外部输入名表示同一个 `u32` 值。例如 `work: a x double alice ;` 和 `work: b x inc bob ;` 都读取 `x`。融合时见证传一次 `x`，锁将其复制到各使用位置。拆分时，`split` 在每个使用 `x` 的工作锁开头写入相同的值，并核对整个输出向量。若独立的门也读取 `x`，门先将其写入拆分锁，再由拆分传给工作锁。运行器从实际花费的前输出读取该值。各分支仍可独立提交。
- `independent-submit:` 要求指定的门、工作或状态阶段单独提交。并行布局有此约束时选择拆分，线性状态布局选择串行。排除理由包含声明的源码行号。 [旧写法](syntax.md#5-兼容语法)
- `workflow-input:` 与 `stage:` 描述线性的状态流程。编译器从值名解析有向依赖并校验唯一来源、栈类型与消费次数。链由一个或多个 `u32 -- u32` 阶段及一个末端 `u32 -- route` 阶段组成，每步声明签名角色。不同角色使用不同公钥。`--current` 在部署时固定初始值。`--available-authorizers` 为首笔花费的可用角色列表。两阶段融合和双输入布局要求两步角色同时可用，串行只要求首阶段角色可用。
- `relation:` 需要先加载 `REQUIRE stdlib/verify.fth`。两个词须具有 `u32 -- u32` 和 `u32 -- route` 栈效果。验证规划器把部署状态、转换和实际后继绑定到一笔花费。 [自动选择](stdlib.md#验证路径)

串行模板从 `deploy:0` 开始，随后各步引用前一阶段的输出 0。每个中间锁以真实部署 txid 和五字节小端 `u32` 开头。后续花费提供从首阶段到直接父交易的原始字节。锁从实际花费的 outpoint 出发，逐笔核对哈希和输入的槽位 0，直至部署根。这种见证随阶段数增长。双输入模板引用同一笔部署的 `deploy:0` 和 `deploy:1`。每个锁依据自己的真实 outpoint 核对完整有序输入向量，运行器核对两个部署输出与构建模板的金额和脚本。各布局的末步都检查按路由选择的有价输出，以及记录部署 txid 和新状态的零值回执。

签名请求包含输入索引及该输入的实际 outpoint。融合可以为同一输入请求多个角色签名，双输入为每个输入分别请求对应角色签名。两步使用同一角色时，融合只请求该输入的一份签名，双输入仍分别签署两份不同原像。

### 交易图

交易构建输出 `transaction_graph`，其 `schema_version` 当前为 1。阶段 DAG 的 `inputs`、`stages` 和 `dependencies` 给出端口类型、生产者、消费者与源码行列。外部输入的生产者为 `null`。值的 `linear` 为真时最多消费一次。传统的 `gate:` 在 DAG 中生成可供两支引用的 `guard`，两支算出的结果仍各由汇合消费一次。

`transactions` 按可执行顺序列出部署及正常步骤。每笔记录执行的阶段、外部见证参数、输入的 `from.step` 和 `from.vout`、输入授权角色和有序输出。正常路径的两个步骤若花费同一符号输出，构建会报错。数据和回执输出是不可花费的终点。`refunds` 给出到期退出转换及其竞争的正常步骤。两者引用同一个库所；其是否可提交取决于真实 UTXO 和当前高度。

`--cpn` 将这些转换和库所渲染成 Mermaid。运行时的 `binding.inputs` 将符号引用连到实际 outpoint 和签名请求摘要。`binding.outputs` 给出签署完成后产生的 outpoint 和金额。复放通过 `artifact_sha256` 与编译决策关联，Script 判定与链上入块状态分别记录。

宿主词使用独立类型。 `bsv-lookup-utxo ( outpoint -- utxo )` 由 UTXO 提供者执行，`bsv-sign ( request -- bytes )` 由外部签名器返回 DER 签名，`bsv-submit ( transaction -- bytes )` 由提交接口执行。 `utxo>outpoint` 和 `utxo>script` 读取已绑定输出。词库描述各自的验证依据，宿主词进入工作词或汇合词的调用链时，构建会报告调用位置和对应的宿主词。

## 构建接口

构建 JSON 通过 `schema_version` 标识格式，记录编译器版本、目标交易版本集合、优化规则、符号输入、被每笔交易执行的源码步骤和脚本字节。`source_sha256` 为源文件原始字节的 SHA-256。核对 `artifact_sha256` 时移除该字段，按键排序，保留数组顺序，将非 ASCII 字符写为 JSON 转义并移除分隔符两侧的空白，再对这些 UTF-8 字节计算 SHA-256。构建结果可在签名前复现，真实父交易和签名仍由实例化阶段绑定。

`--explain` 报告候选的约束、选择和每笔交易的符号父输出。成本估算使用报告中列出的固定见证长度和数据样本。自动选择先排除不符合约束的候选，再依次按整条路径字节、单笔最大签名验证次数和依赖深度排序。完全同分时优先融合。可用性说明本次能同时取得的数据和角色，交易模板逐步列出各自仍需提供的输入与签名。

每个合格候选的 `artifact_sha256` 是同一配置下普通构建 JSON 的摘要。包含 `schedule_explanation` 的 JSON 对整份文档另算自己的 `artifact_sha256`。复放格式 2 保留普通构建 JSON，按源码、候选构建摘要和路由标注每条路径。离线报告并列显示静态候选资格和复放状态，并核对实际交易图及终端输出。复放中的耗时只用于报告。固定的证据输入生成可重复的报告，新的 regtest 运行会记录新的交易和采样。 [报告生成命令](../toolchain.md#编译决策报告)

共用外部输入的计划使用 `schema_version` 2。`shared_input` 给出输入名，每个交易模板的 `external_inputs` 按见证从栈底到栈顶的顺序列出该步需要提供的值。动态输出中的 `prefix_u32_input` 指定前缀的数据来源。锁脚本依次拼接压栈操作码 `05`、四字节小端无符号值、符号字节 `00` 和 `script_suffix_hex`。只使用独立输入名的计划沿用格式 1。

`--join-witness shared` 每个汇合输入只放一次两笔结果交易共用的锁脚本后缀。Script 先按原顺序拼回两笔完整交易，再核对两者实际 outpoint、同一拆分来源和后继输出。`full` 使用原始见证布局。

`--search` 枚举已支持的交易形状。拆分候选先核对每个工作输入对应的拆分槽位，以及汇合消耗的两个有序结果输出。门与拆分合并要求同一授权角色和同时可用的门输入、签名及允许融合的源码约束。门单独提交仍须在自身交易中验证条件与签名，拆分随后绑定该输出。独立提交的工作步骤保留自己的交易。

`path-bytes` 依次比较整路字节、最大单笔签名检查次数和依赖深度。`peak-validation` 依次比较最大单笔签名检查次数、最大单笔输入脚本字节、整路字节和依赖深度。输入脚本字节是每笔交易各输入的解锁脚本与所花费锁脚本长度之和。两个目标同分时按候选名排序。峰值验证排序使用静态代理指标，报告另列两引擎实测耗时及每条路径的字节偏差。复放格式 3 按候选构建摘要关联两条路由，报告器也可读取既有格式 2。

`--optimize stack` 在安全降栈后分析基本块里的值和最后一次使用。它按栈深选择浅层取数指令或 `PICK`、`ROLL`，在已证明总能执行的基本块内复用相同计算。候选字节码更短时才替换原块。两个 `IF` 分支分别处理，栈输出顺序仍由 Forth 定义决定。

`stack-local-operand-scheduling` 在同一个基本块中尝试复用栈顶最后使用的值以及成对取栈。它只对完整字节码为一个可交换操作码的二元运算比较两个操作数顺序。记录的 `basis` 给出总性、剩余引用数和输出顺序条件，`script_bytes` 给出改写前后的字节数。

`--optimize baseline` 使用原有字节码后端。`--optimize safe` 在带类型的栈表示上做范围分析和分支指令选择。输出的 `rewrites` 记录规则、源码行列及触发规则的栈类型和范围。单独导出的词遵循 `takes` 中的数值范围，交易模板在进入计算前检查外部输入范围。

`--capabilities` 输出机器可读的词集、执行位置和交易版本清单。 `--entry <word>` 只编译指定的已标注定义，便于检查 Script 字节和栈签名。事务构建在发现首个无效使用时退出，并指明源文件行列。诊断区分未知词、无法下沉的标准词和调用链中的宿主词。

### 钱包锁中的数值公式

构造钱包锁的 `ScriptBuilder` 支持 `formula:`。栈效果使用已声明的 `script-int` 范围，`{: ... :}` 为输入命名，`let` 将栈顶结果赋给一个局部名称。名称可以反复读取。末尾留在栈上的值按声明顺序返回。

```forth
range: small script-int 0 11 ;
range: squared script-int 0 101 ;

formula: square ( small -- squared )
    {: x :}
    x x int*
;
```

`int-from-bottom INDEX RANGE` 读调用者留在栈底的数值，索引从零开始。调用者负责保证输入与栈底值采用规范的 ScriptNum 编码并符合声明范围。编译器沿公式推导中间量范围，检查输出范围与 Genesis 数值长度上限，并要求 `int-rem` 的除数有可证的正下界。

优化构建比较原顺序发码、依赖图调度和加入等价改写的候选，按序列化字节数选择。报告给出候选字节数、选中规则及源码的中间量位宽上界。P2PKH-R1 用这条路径编译 P-256 的点加和倍点。 [源码和复放](../../projects/p2pkh-r1/experiments/forth)

编译器保存公式的中间表示。调用构造器能证明某个参数为常量时，可在生成字节前绑定该参数并重新推导中间量范围，生成少一个运行时输入的内核。R1 的仿射点加只在选中的固定生成元表项满足 `Z=1` 时进入该内核，零下标由组单位元分支处理。 [R1 前置扫描和候选](../../projects/p2pkh-r1/experiments/forth/README.md#点乘窗口候选)

## 电路入口

`circuit_backend.py` 根据阶段依赖选取一个 `u32 -- u32` 转换词和一个 `u32 -- route` 路由词。仅有词定义的文件须通过 `--entries TRANSITION ROUTE` 指定入口。带工作流声明的文件以声明为准。本入口编译计算和路由，交易签名与独立提交仍由交易规划器处理。

当前 Circom 后端支持整数字面量、栈重排、字面量的 `cell>u32`、`u32+`、`u32<`，以及由字面量或受支持比较结果驱动的 `IF`。用户定义的词展开后使用同一规则，无法生成约束的操作报告源码行列。电路限制为 128 个展开操作和 256 个估算线数。 [示例与复放命令](../toolchain.md#从-forth-生成约束)

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol --capabilities
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
```

版本目标与词集、运算语义和调度分别配置。 `--target both` 让同一份锁接受版本 1 和 2，选 `Contracts.prepare(..., version=1)` 或 `version=2` 在实例化每步时决定实际版本。锁验证当前交易和每份结果父交易自身的版本及来源。版本进入签名摘要，改动父交易版本后须重新绑定其后继。

## 电路后端

电路源码声明 `advance ( u32 -- u32 )` 和 `decide ( u32 -- route )` 两个带栈效果注释的定义。后端支持整数字面值、字面 `cell>u32`、现有栈排列、`u32+`、`u32<`、路由字面值和以字面值或 `u32<` 标志驱动的 `IF`。`u32<` 的 Forth 真值为 `-1`，电路在选择分支时用相应的布尔位。生成超出操作或线宽预算的电路，以及无法生成约束的词，都会报告源码行列。

生成的约束将 `next` 与 `route` 作为公开输出。交易绑定还使用 `current`、`bindLo` 和 `bindHi`。Circom 和 snarkjs 负责生成 R1CS 以及计算和检查完整赋值，4thGraph 把透明验证器和后继锁编译为 Script。详见 [重跑命令](../toolchain.md#从-forth-生成约束)。
