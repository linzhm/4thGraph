# 4thGraph 语法书 · v0.2.7

本书定义 4thGraph 的源码词法、规范声明语法和兼容语法。标准词采用 Forth 2012 Core 在本实现支持范围内的语义。栈类型、整数范围与交易布局见 [语言语义](language.md)。[Forth 2012 Core](https://forth-standard.org/standard/core)

## 1. 记号

- 源文件使用 UTF-8。`CRLF` 和 `CR` 统一为 `LF`。空白分隔记号，换行和空格在解析声明时等价。`;`、`--`、`:`、`IF`、`ELSE`、`THEN` 各自占一个记号。`work:` 和 `relation:` 各是一个完整记号。
- 独立的 `(` 记号开始注释，读到下一处 `)` 即结束。支持跨行。独立的 `\` 记号从当前位置注释到行尾。注释可出现在记号之间。
- 关键字和词名查找使用 Unicode case folding。文档、模块目录和构建产物中的规范词名使用小写。原始拼写和行列可出现在诊断里。
- 文法中的 `symbol` 在 case folding 后匹配 `[a-z][a-z0-9_-]*`，用于阶段、角色、值名、范围名和 `relation:` 引用的词名。一般定义名和由 `work:`、`gate:`、`join:` 查找的计算词是单个记号，可使用 `+` 一类拼写。
- `REQUIRE` 读取同一行的文件名，文件名按原拼写处理。4thGraph 先在当前源码文件所在目录解析相对路径，再查询打包的标准库。通过内存源码接口调用且没有源路径时，以当前工作目录为起点。
- `bsv-` 前缀保留。应用不能用它声明新词。扩展词的执行位置由接口给出，例如 `bsv-sign` 由宿主执行。

## 2. 规范文法

以下使用 EBNF。引号内为字面记号，`[ … ]` 表示可选，`{ … }` 表示可重复零次或多次。`nonspace` 表示非空白字符。数字和文件名各是一个连续记号，`REQUIRE` 的文件名与命令同一行。

```ebnf
source           = { item } ;
item             = requirement | definition | declaration ;
requirement      = "require", filename ;
filename         = nonspace, { nonspace } ;
alphanumeric     = ascii-letter | digit ;
symbol           = ascii-letter, { alphanumeric | "_" | "-" } ;

definition       = ":", word-name, stack-effect, { instruction }, ";" ;
stack-effect     = "(", { stack-type }, "--", { stack-type }, ")" ;
instruction      = call | cell-literal | byte-literal | range-check | branch ;
call             = word-name ;
byte-literal     = "bytes-hex", hex-pairs ;
range-check      = "check-range", symbol ;
branch           = "if", { instruction }, [ "else", { instruction } ], "then" ;

declaration      = range | work | join | gate | split-authority | recovery
                 | independent | workflow-input | stage | relation ;
range            = "range:", symbol, numeric-type, integer, integer, ";" ;
work             = "work:", symbol, symbol, word-name, symbol, ";" ;
join             = "join:", symbol, symbol, symbol, word-name, ";" ;
gate             = "gate:", symbol, symbol, word-name, symbol, ";" ;
split-authority  = "split-authority:", symbol, ";" ;
recovery         = "recovery:", block-height, symbol, ";" ;
independent      = "independent-submit:", symbol, ";" ;
workflow-input   = "workflow-input:", symbol, "u32", ";" ;
stage            = "stage:", symbol, symbol, symbol, symbol, symbol, ";" ;
relation         = "relation:", symbol, symbol, ";" ;

stack-type       = built-in-type | declared-range | backend-type ;
built-in-type    = numeric-type | "bytes" | "script" | "transaction"
                 | "utxo" | "outpoint" | "request" ;
numeric-type     = "cell" | "u32" | "route" | "script-int" ;
integer          = decimal | "#", decimal
                 | "$", signed-hex | "%", signed-binary ;
decimal          = [ "-" ], digit, { digit } ;
signed-hex       = [ "-" ], hex-digit, { hex-digit } ;
signed-binary    = [ "-" ], binary-digit, { binary-digit } ;
hex-pairs        = hex-digit, hex-digit, { hex-digit, hex-digit } ;
cell-literal     = integer | quoted-character ;
```

`ascii-letter` 为 `a–z`，`digit` 为 `0–9`，`binary-digit` 为 `0` 或 `1`，`hex-digit` 为 `0–9`、`a–f` 或 `A–F`。`decimal`、`signed-hex`、`signed-binary` 和 `hex-pairs` 各为一个连续记号。使用进制前缀时，负号写在前缀后，例如 `$-ff`。`block-height` 为 1 至 9 位十进制数字，值域为 1 到 499,999,999。字符字面量由两个单引号包住一个可打印字符，例如 `'A'` 和 `' '`。数字和字符字面量产生 `cell`。数字字面量接受 `[-2^63, 2^64)` 内的整数，并归一化到有符号 64 位 cell。范围边界按数学整数读取。`word-name` 是一个记号，定义名需避开控制词、源声明、已导入的词和保留前缀。`call` 须解析到内置、已导入或已定义的词。

## 3. 声明与解析

| 声明 | 参数顺序与约束 |
| --- | --- |
| `REQUIRE` | 读取同一行的一个文件名，在该位置加载源码 |
| `( 输入类型 -- 输出类型 )` | 紧跟定义名。两侧按栈底到栈顶书写，可为空 |
| `range:` | 范围名、数值基类型、包含的下界、排除的上界。区间应非空并落在基类型范围内 |
| `work:` | 步骤、输入值、计算词、签名角色。词的栈效果须为 `u32 -- u32` |
| `join:` | 步骤、左工作步骤、右工作步骤、路由词。词的栈效果须为 `u32 u32 -- route` |
| `gate:` | 步骤、输入值、门控词、签名角色。词的栈效果须为 `u32 -- cell`，非零允许继续 |
| `split-authority:` | 拆分签名角色 |
| `recovery:` | 绝对区块高度、退款签名角色。锁绑定该高度，最早确认区块为高度加一 |
| `independent-submit:` | 一个门、工作或线性状态阶段，要求它具有独立交易边界 |
| `workflow-input:` | 初始值名、类型 `u32` |
| `stage:` | 阶段名、计算词、输入值名、输出值名、签名角色。值连接形成有向依赖 |
| `relation:` | 转换词、路由词。栈效果依次为 `u32 -- u32` 和 `u32 -- route` |

- 顶层指令和声明在读取源码时生效。普通计算、转换、构造和验证词通过定义体调用。
- 冒号定义名之后紧跟一个包含 `--` 的栈效果注释。标准 Forth 按普通注释处理，4thGraph 将其用作静态类型合同。签名只能引用当时已知的栈类型。定义体调用在解析到该位置时已定义、导入或内置的词。`IF` 从栈上消费一个 `cell`，两条分支合并时的栈类型和顺序须一致。
- `work:`、`gate:`、`join:` 在读取时查找计算词。`join:` 的工作步骤、`stage:` 的计算词与值依赖、`relation:` 的两个词在构建对应计划时解析。`stage:` 可以按与依赖顺序不同的次序书写。
- 并行计划需要两个不同的工作步骤、一个汇合和一个拆分签名角色，可附带一个门。线性计划需要一个初始值、一个或多个 `u32 -- u32` 阶段，以及最终的 `u32 -- route` 阶段。每个线性值只有一个生产者，并且最多消费一次。两阶段支持 `fused`、`serial` 和 `atomic`，更长的链使用 `serial`。`deploy`、`split`、`fused` 为保留的步骤名。两类计划均可附带一个退款规则及独立提交约束。 [交易图](language.md#交易图)
- `relation:` 须先执行 `REQUIRE stdlib/verify.fth`。一个关系文件至多声明一个关系，且独立于交易流程声明。它给编译器提供要验证的状态关系。编译器按后端能力、策略和预算选择同一关系的实现。 [关系构建与复放](stdlib.md#验证路径)

栈效果注释描述词的输入和输出，由 4thGraph 静态核对。`range:`、`work:` 和 `relation:` 则是显式声明。它们分别影响数值检查、交易调度和验证关系。声明词借用 Forth 定义词的写法，每种声明有自己的参数和结束符。Forth 2012 的 `CREATE` 与 `DOES>` 提供了在完整 Forth 系统中实现定义词的机制。 [Forth 2012 CREATE](https://forth-standard.org/standard/core/CREATE) · [Forth 2012 DOES>](https://forth-standard.org/standard/core/DOES)

TypeScript 的 JSDoc 类型是工具读取注解的例子。Rust 属性提供显式语法，可参与编译处理。4thGraph 采用同样的区分，把类型合同放在词定义处，把影响交易或验证的约束写成可见的源码声明。 [TypeScript JSDoc](https://www.typescriptlang.org/docs/handbook/jsdoc-supported-types.html) · [Rust 属性](https://doc.rust-lang.org/reference/attributes.html)

## 4. 公开导出

文件通过 `REQUIRE` 在调用方的词典中解析，同一文件每次构建只加载一次。随后定义的同名词对后续调用生效。之前的定义继续引用其编译时绑定的词。标准库清单记录约定的公开接口及后端要求。相对文件依赖、加载循环、栈签名错误和不支持的后端都有构建诊断。

| 拼写 | 合同 |
| --- | --- |
| 类型加操作 | 类型确定操作域。例如 `u32+` 是 32 位回绕加法，`bytes-cat` 拼接字节 |
| `源>目标` | 显式转换，接口说明截断、扩展、编码和越界行为 |
| `…?` | 返回 Forth flag。真为 `-1`，假为 `0`。`u32<` 和 `bytes=` 保持各自的比较运算拼写 |
| `…-lock` | 构造序列化的锁定 Script。参数和返回值由栈签名定义，交易输出由调用方绑定 |
| `…-verify` | 失败终止当前执行。成功后的返回值由栈签名定义。算法及影响互操作的参数写入词名 |

`protocol.py --capabilities` 的 `bsv.source_syntax` 给出规范声明及兼容形式。`libraries.<module>.interfaces.<word>` 的记录采用以下字段。

| 字段 | 内容 |
| --- | --- |
| `name`、`module`、`aliases` | 规范名、所属模块、可解析的兼容名列表 |
| `takes`、`gives` | 从栈底到栈顶排列的类型列表。导入时核对实际词定义 |
| `build_parameters`、`runtime_inputs`、`transaction_context` | 参数列表，每项有 `name`、`type`、`description`。空列表表示该接口无对应要求。运行时输入也可描述由后端解包的花费见证 |
| `failure_mode`、`failure` | `total` 表示对声明域内输入有定义。`abort` 表示违反验证条件时终止。`failure` 描述适用条件 |
| `backends` | 支持该接口的编译或执行后端 |

`groth16-bls12-381-verify` 的验证密钥在构建时固定，证明及动态公开信号由花费提供。它返回 `groth16-verified` 成功标记。若应用还要约束当前 outpoint、输出或授权，应在关系或交易层明确表达。

构建产物的 `libraries` 记录实际加载的文件和源码原始字节的 `sha256`。已登记的标准库另有公开接口的 `interface_sha256`。接口摘要对去掉摘要字段后的模块描述按键排序并紧凑序列化 JSON 后计算 SHA-256。Groth16 构建另记录验证密钥原始字节的 `verification_key_sha256`。

## 5. 兼容语法

新源码采用第 2 节的规范写法。编译器仍读取下面的旧形式。

| 兼容写法 | 规范写法 |
| --- | --- |
| 独立的 `bsv-effect: name inputs -- outputs ;` | `: name ( inputs -- outputs ) … ;` |
| `work:`、`join:`、`gate:`、`split-authority:`、`recovery:` 省略最后的 `;` | 每个声明有独立的结尾 `;` |
| `independent-submit step` 或已定义的门或工作步骤 `step independent-submit` | `independent-submit: step ;` |
| `verify: transition route ;` | `relation: transition route ;`，仍用 `REQUIRE stdlib/verify.fth` |
| `groth16-verify` | `groth16-bls12-381-verify` |

固定参数声明的兼容形式按上述参数个数结束。省略终止符的规则只适用于表中的五种冒号声明。兼容的前缀 `independent-submit` 也可接受分号。新拼写 `independent-submit:` 和两种关系拼写都要求分号。Groth16 别名使用同一验证语义，构建产物按规范名记录。

## 6. 最小关系程序

```forth
REQUIRE stdlib/u32.fth
REQUIRE stdlib/verify.fth

: decide ( u32 -- route ) 20 cell>u32 u32< if route-review else route-settle then ;

relation: u32-inc decide ;
```

`4thgraph-circuit` 生成 Circom。`4thgraph-verify` 构建交易绑定和后端选择报告。 [完整命令](stdlib.md#验证路径)
