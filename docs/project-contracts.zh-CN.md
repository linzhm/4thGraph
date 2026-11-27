# 4thGraph 构建、夹具与项目合约接口

4thGraph 目前把 Forth 编译为 BSV Script。脚本作者用命名值描述计算，编译器负责排栈。人或 agent 都可以给同一个入口提交一个固定计划，或者在冻结的输入上提交多套计划。钱包用途还需要项目提供的 WASM。模块文件名由项目决定，宿主按版本清单查找。

```text
Forth 源码、依赖、计划 → ScriptBuilder → Formula / Step → Graph → 栈调度与发射
                                                              ↓
                                                 精确 Script、布局、指令清单
                                                              ├─ 公式夹具 → 字节、双栈、时间、差额
项目的 Go 源码 → 独立 WASM 构建 → 项目合约模块 ──────────────────┤
                                                              └─ 项目 manifest
                                                                   ↓
                                     实际父输出 → 识别 → 准备 → 宿主授权 → 组装
                                                                   ↓
                                                   完整花费验证 → 回执及公开重放
```

### 按编译目标构建 PELS 锁

用普通 Forth 计算预期输出。以下锁的业务条件是一个输入、两项有序输出及 `nLockTime = 42`。调用方把收款脚本作为构建参数绑定。单输入的交易上下文见证由编译器和组装器确定。

```forth
REQUIRE stdlib/pels.fth
bytes-param: recipient-lock 25 ;

: payout ( -- output ) 9999 1+ recipient-lock tx-output ;
: receipt ( -- output ) 0 bytes-hex 006a055245414459 tx-output ;

lock: settle ( )
    1 inputs= verify
    payout receipt 2 outputs= verify
    tx-locktime 42 = verify
;
```

```sh
4thgraph settle.fth --entry settle --bind-bytes recipient-lock="$RECIPIENT_SCRIPT_HEX" \
  --target chronicle-v2 --sighash-family auto --explain > lock.json
4thgraph pels-witness lock.json --parent parent.hex --unsigned unsigned.hex
```

`parent.hex` 是实际包含编译锁的父交易。候选交易必须花费该输出并满足上述锁的断言。用 `--sighash-family both` 构建时，组装要显式传 `--sighash-family bip143` 或 `otda`。组装器只填见证，适用的 Chronicle 规则随构建路径记录。独立交易验证应使用实际父交易和对应链上下文。

两条实验轴可各自重跑。固定目标和编译器，比较 Forth 源码修改。固定源码和参数，比较目标内的原像布局及汇编实现。构建报告记录 `source_sha256`、`constraints_sha256`、候选的 `script_sha256`、各片段的散列与依赖边，以及花费路径的签名锚点。`--explain` 保留所有候选字节。比如 `9999 1+` 和 `10000` 源码摘要不同，这个锁的业务约束摘要和最终字节却相同。[实验入口与比较报告](#公式优化与-agent-的两轮实验)

### 做一次构造测试

以 R1 的普通 ForkID ALL 路径为例。命令从 Forth 重建模板并对照冻结的 v0.6.0 字节，独立编译 WASM，在内存生成本轮 P-256 密钥，将所选公钥的 HASH160 填入模板并构造合成父交易。宿主核对候选后签名，比较 WASM 与既有参考实现生成的见证字节，再把组装好的交易与实际父交易交给 chain-gang。临时私钥只在签名进程内使用。回执保存公钥、父交易、签后交易以及各用例结果。需要逐项比对材料时，验证器的 `--include-io` 会保存入口的实际输入、期望与返回值。

在仓库根目录使用项目现有 Python、Node.js 和 Go 环境。重建预编译模块需要支持 WASI reactor 的 Go，提交产物使用 Go 1.25.14。Node.js 的 WASI preview1 运行项目模块。独立合约包的验收引擎默认为固定版 chain-gang，BSV Node 1.2.3 为显式可选复核。[验证依赖](../tools/requirements-chronicle.txt)

```sh
export PYTHONPATH=src:.
python tools/build_project_contract.py p2pkh-r1 workspace/holder --smoke
```

`workspace/holder/smoke.json` 记录临时密钥这一轮的结果。冷构建相同工具、源码与参数得到相同 Script、模块与 manifest。临时密钥每轮不同，因此公钥、实例化的锁和交易也会不同。可重复的回归使用固定公开测试密钥或该路径约定的无签名见证。下面两条命令重建包，实跑固定夹具，将签后交易与实际父交易交给 chain-gang 并生成 `receipt.json`。

```sh
python tools/build_project_contract.py p2pkh-r1 workspace/holder --verify
python tools/build_project_contract.py pels-counter workspace/counter --verify
```

下面的命令用保存的公开材料重放签后交易。也可对 `smoke.json` 做相同重放。批准值来自仓库中这版 R1 包的清单。可用 `--public-key HEX` 指定本地选定的公开身份。默认实跑及重放的级别均为 `chain-only`，引擎判定中的 `bsv_node` 记录为 `not_run`。

```sh
python tools/verify_project_contract.py workspace/holder/manifest.json \
  --approved-sha256 2dddac4e7a9eb6b2f08a16357c2db78461b6fc0e37b429c8fff29c4b64ef3d97 \
  --replay workspace/holder/receipt.json --output workspace/holder-replay.json
```

显式选择双引擎时，向上面的验证或重放命令追加 `--with-bsv-node`，并设置隔离 regtest 的 `REGTEST_URL` 和 `REGTEST_COOKIE`。例如下列调用主动启动本地 BSV Node 作一次复核。显式选用后，连接、版本或判定失败都会报告错误。独立合约包的回执覆盖夹具中的 Script 花费，交易入池、入块和正式 MESA 验收须分别取证。

```sh
bash tools/verify_node.sh --profile raised -- python tools/verify_project_contract.py \
  workspace/holder/manifest.json --approved-sha256 2dddac4e7a9eb6b2f08a16357c2db78461b6fc0e37b429c8fff29c4b64ef3d97 \
  --replay workspace/holder/receipt.json --with-bsv-node --output workspace/holder-node-replay.json
```

### 标准逻辑接口

| 入口 | 实际输入 | 成功输出 | 典型错误 |
|---|---|---|---|
| `recognize` | 实际 prevout 的 wire outpoint、金额、锁字节；项目需要的本地公开上下文 | `Match` 和解析出的模板参数。R1 还核对选定公钥确实属于该锁 | `MissingContext`、`NoMatch`、`NotOwned` |
| `prepare_spend` | 同一 prevout、候选交易、输入序号与获准路径 | `Prepared`，绑定精确候选摘要、outpoint、输入序号、路径、签名模式、原像和摘要 | `UnsupportedPath`、`InvalidSuccessor`、`CandidateMismatch` |
| `assemble_unlock` | 同一候选和前序、前一步的材料、宿主返回的授权 | `Assembled` 和该输入的解锁字节 | `CandidateMismatch`、`InvalidAuthorization` |

ABI 标识为 `4thgraph.project-contract/1`。请求与回应用 UTF-8 JSON，字节串用十六进制，金额以整数聪计。outpoint 用 32 字节 wire 顺序 txid 加小端 vout。宿主调用 `abi_buffer(n)` 申请线性内存，写入请求后调用相应导出函数，传入长度。64 位返回值的高 32 位是返回区指针，低 32 位是字节数。请求与响应各限 8 MiB。模块的 WASI 环境没有预开放目录。R1 使用宿主提供的 HASH160 原语。[Go 数据类型](../sdk/go/contractabi/contract.go) · [WASM ABI](../sdk/go/contractabi/reactor_wasip1.go) · [运行适配器](../src/fourthgraph/workflow/contract_runtime.mjs)

宿主从本地认可的 manifest 摘要起步，检查模块与模板的精确摘要、参数槽和签名锚点。钱包程序从真实父交易取输出，按输入的 outpoint 对齐。宿主独立序列化候选、计算签名覆盖，签名回调可以查看完整父交易、候选、序号、路径与摘要。宿主只替换获准输入的见证，最后由独立验证器复核。收到未知模板时，`NoMatch` 表示这个钱包缺少匹配的项目包，链上有效性由交易验证决定。[宿主](../src/fourthgraph/workflow/project_contract.py)

功能 Profile 选择本地理解的项目，模板版本固定具体的 Script、布局与 WASM。单次签署候选用精确交易字节绑定。模板字节升级要保留旧包以花费旧 UTXO。多步流程逐笔引用已构造并验证的父输出。PELS 归属标准库模板族。此处的 `pels-counter` 实例选用单输入、单后继、固定费用及保留代码的 `advance` 路径。R1 包支持 v0.6.0 的 `ordinary-all` 路径，MESA 签名槽对签后逆元的支持仍待单独评审。[模板族及优化接入评审](optimizer-integration-review.zh-CN.md)

当前项目包宿主验证 BIP143 ALL（`0x41`）。将来接入 OTDA 或 PELS 多模式成员时，编译器根据项目语义匹配并链接实现，模板清单按具体路径绑定已编入的 sighash、有效 `scriptCode`、见证布局、已认证字段和适用链规则。一次 `prepare_spend` 使用一种已编入的模式，宿主按该路径重算原像并核对覆盖后再授权。[模式及约束表](optimizer-integration-review.zh-CN.md#用什么模板验证什么内容)

### 夹具可以追加错误输入

每个项目在 `contract/cases.json` 中指定 `id`、`entry`、对固定请求的 `patch` 和 `expect`。期望可以引用独立计算的 `$prepared` 和 `$expected_unlock`。下面是 R1 真实用例，验证拒绝发生在宿主签名之前。

```json
{"id":"wrong-owner-before-sign","entry":"host_spend",
 "patch":{"pubkey":"$other_key"},
 "expect":{"status":"NotOwned","signer_calls":0}}
```

返回错误时还检查响应不含待签材料和解锁脚本。既有用例覆盖三入口的正常返回、缺少前序、输入类型错误、未知模板或路径、错误公钥、缺签、已覆盖输出变化和错误后继。`pels-counter` 分别运行两个状态阶段，第二步使用第一步实际组装的交易作为父交易。新增同类用例只需扩充表并重建本地包，新 manifest 显式绑定更新后的夹具摘要。[R1 用例](../projects/p2pkh-r1/contract/cases.json) · [计数实例用例](../projects/pels-counter/contract/cases.json)

### 公式优化与 agent 的两轮实验

使用安装后的 `4thgraph experiment`，或在设置 `PYTHONPATH=src:.` 后以 `python -m fourthgraph.workflow.protocol experiment` 运行。下面的客户端只读取上一轮 JSON 就能得到下一批请求。第二轮的枚举和冷重放都不需要模型。

```sh
mkdir -p workspace/formula
4thgraph experiment capabilities
echo '{"fixture":"bezier","workers":2,"plans":[{},{"passes":["stack"]},{"passes":["rewrite","share","stack"]}]}' |
  4thgraph experiment run - > workspace/formula/first.json
4thgraph experiment next workspace/formula/first.json > workspace/formula/next.json
4thgraph experiment run workspace/formula/next.json --parent workspace/formula/first.json > workspace/formula/second.json
4thgraph experiment replay workspace/formula/second.json --parent workspace/formula/first.json
```

冻结信息包括源码、依赖、工具和向量摘要。默认报告给出请求与实际计划、每项编译/测试状态、字节及 SHA-256、两栈峰值、编译耗时、基线与父项差额、可行后续操作和停止原因。时间是本机观测值，冷重放核对语义结果与身份。公式运行未测到调用方或整笔交易的指标会显示 `not_measured`。可选 `"trace":true` 输出源码位置、别名、依赖、语义步骤快照及最终指令；尚未采集的目标层逐步栈图在报告中标明。

| 夹具 | 对照 | 本分支结果 | 验收边界 |
|---|---|---|---|
| Bézier，冻结源码 | 基线 → 两个父计划 → 各自追加搜索 | 118 → 47 / 47 → 47 / 46 B；最后两项的主栈峰值为 9 / 10，备用栈均为 1 | 每项 625 组向量，精确返回字节与两栈保留 |
| `square`，冻结源码 | 基线 → 栈调度 → 加搜索 | 6 → 3 → 3 B，同分保留较简单父计划 | 每项 11 组向量 |
| Bézier，冻结 `stack` 计划 | 多项式展开式 → 两级线性插值 | 47 → 37 B，主栈峰值 9 → 8 | 两个独立源码身份，同一组 625 个 oracle；尚未验证调用方净收益 |
| R1 构造夹具 | 41,364 B 的 v0.6.0 模板，花到单个 `OP_1` 输出 | 见证 326 B，签后交易 389 B | 固定夹具双引擎；这里量的是消费交易 |
| `pels-counter` 实例夹具 | 705 B 的状态锁，0 → 1 → 2 | 每步见证 860 B，签后交易 1,629 B | 两笔消费均有双引擎历史回执 |

本机对 Bézier 做了 5 轮串行测量，编译时间从开始处理单项计划计到发射 Script，排除向量执行。三项 `rewrite/share/stack` 的中位数是 2.34 ms，加入 `search` 后为 177.72 ms。这里用额外编译时间和一个主栈槽换取了 1 B。这是本次环境的测量值。

A 轴固定来源。#82 提供的 12 组合法开关可用 `{"fixture":"bezier","enumerate":"sets"}` 枚举；`search` 必须依赖 `stack`，在图上选择终端排布。单独的有序实验用 `{"fixture":"bezier","enumerate":"orders","depth":3,"terminal":["stack"]}`，在输入契约内依次应用 `double-as-add` 和 `common-values`。当源码同时含 `2*x` 与 `x+x` 时，先代换再共享可合并来源；先共享再代换则需要重跑共享。枚举键含完整语义节点、来源、剩余深度，同一枚举内契约和终端固定。无变化停止；验证缓存另以冻结环境与实际字节摘要为键。每次最多 32 个候选、4 个工作线程，时间预算在批次间检查。

B 轴固定编译计划与夹具，比较登记过的不同算法源码。等价依据是两个 Bézier 算法满足同一个整数多项式恒等式，区间检查与回归补充验证。报告保留两份源码身份。对于调用方的栈转换、整锁、交易成本，还需要一次真实集成测量。外部 agent 可按预算提名已登记的规则、顺序或实现；当前入口接受结构化数据，验证由工具和夹具执行。

### 开发计划与评审边界

| 工作包 | 仓库落点 | 验收 |
|---|---|---|
| 1. 原生实验入口 | `src/fourthgraph/benchmark` 和现有 CLI | Bézier 和 square 两轮、机器报告驱动、冻结重放 |
| 2. 公式语义和终端排布 | `src/fourthgraph/compiler` | 累积来源、区间前提、依赖及源码顺序最后使用点；显式有序计划与 #82 集合分开测试 |
| 3. 钱包构建包 | 共享 ABI、项目自己的 WASM 源码、版本目录与 manifest | 从模块任意文件名加载；保留单独可读的 Script、反汇编、参数与签名锚点 |
| 4. 两个项目的实际花费 | 各自的 `contract/cases.json` 与回执 | R1 临时与固定测试密钥、`pels-counter` 实际前序两步。默认 chain-gang，显式可再用 BSV Node 核验 |
| 5. 算法与顺序对照 | 显式 A/B 请求、依赖约束和有限规则集合 | 同范围相同成本口径比较；只有测过完整调用方才能作采用决定 |
| 6. 后续评审 | 有代表性的实际调用方与完整交易夹具 | 净收益稳定后再评审重算或新规则；付费模型、发行默认变动、跨脚本全局优化均需独立决定 |

高层与栈排布分离借鉴 Yul 对表示和优化阶段的处理。这里的成本由 BSV Script、实际交易字节、栈峰值和编译耗时给出。公式规则只接收直线、规范编码、有限范围的整数图，除数需要正下界；输入声明是调用方前提。验证失败顺序、控制分支、缓存栈底槽、签名与 CODESEPARATOR 均是移动界限。钱包模板的最终字节作为单独产物原样打包。[Solidity optimizer](https://docs.soliditylang.org/en/latest/internals/optimizer.html) · [4thGraph 公式规范](language/specification.md#钱包锁中的数值公式)
