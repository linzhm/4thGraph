# 独立项目包与 WASM 花费夹具

[English](project-contracts.md)

项目包将已编译的精确 Script、清单及对应 WASM 配对。下面以 R1 普通付款和 PELS Counter 为两个应用示例。

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
  --approved-sha256 38d4a27b01e35821107fdc7d49b2df04320ff406de7c672a78f95598d0bc1f8d \
  --replay workspace/holder/receipt.json --output workspace/holder-replay.json
```

显式选择双引擎时，向上面的验证或重放命令追加 `--with-bsv-node`，并设置隔离 regtest 的 `REGTEST_URL` 和 `REGTEST_COOKIE`。例如下列调用主动启动本地 BSV Node 作一次复核。显式选用后，连接、版本或判定失败都会报告错误。独立合约包的回执覆盖夹具中的 Script 花费，交易入池、入块和正式 MESA 验收须分别取证。

```sh
bash tools/verify_node.sh --profile raised -- python tools/verify_project_contract.py \
  workspace/holder/manifest.json --approved-sha256 38d4a27b01e35821107fdc7d49b2df04320ff406de7c672a78f95598d0bc1f8d \
  --replay workspace/holder/receipt.json --with-bsv-node --output workspace/holder-node-replay.json
```

### 标准逻辑接口

| 入口 | 实际输入 | 成功输出 | 典型错误 |
|---|---|---|---|
| `recognize` | 实际 prevout 的 wire outpoint、金额、锁字节；项目需要的本地公开上下文 | `Match` 和解析出的模板参数。R1 还核对选定公钥确实属于该锁 | `MissingContext`、`NoMatch`、`NotOwned` |
| `prepare_spend` | 同一 prevout、候选交易、输入序号与获准路径 | `Prepared`，绑定精确候选摘要、outpoint、输入序号、路径、签名模式、原像和摘要 | `UnsupportedPath`、`InvalidSuccessor`、`CandidateMismatch` |
| `assemble_unlock` | 同一候选和前序、前一步的材料、宿主返回的授权 | `Assembled` 和该输入的解锁字节 | `CandidateMismatch`、`InvalidAuthorization` |

ABI 标识为 `4thgraph.project-contract/1`。请求与回应用 UTF-8 JSON，字节串用十六进制，金额以整数聪计。outpoint 用 32 字节 wire 顺序 txid 加小端 vout。宿主调用 `abi_buffer(n)` 申请线性内存，写入请求后调用相应导出函数，传入长度。64 位返回值的高 32 位是返回区指针，低 32 位是字节数。请求与响应各限 8 MiB。模块的 WASI 环境没有预开放目录。R1 使用宿主提供的 HASH160 原语。[Go 数据类型](../sdk/go/contractabi/contract.go) · [WASM ABI](../sdk/go/contractabi/reactor_wasip1.go) · [运行适配器](../src/fourthgraph/workflow/contract_runtime.mjs)

`prevout.amount` 必须显式传入整数，0 聪写为 `0`。省略该字段或传入 `null` 时，模块返回 `MissingContext`。

宿主从本地认可的 manifest 摘要起步，检查模块与模板的精确摘要、参数槽和签名锚点。钱包程序从真实父交易取输出，按输入的 outpoint 对齐。宿主独立序列化候选、计算签名覆盖，签名回调可以查看完整父交易、候选、序号、路径与摘要。宿主只替换获准输入的见证，最后由独立验证器复核。收到未知模板时，`NoMatch` 表示这个钱包缺少匹配的项目包，链上有效性由交易验证决定。[宿主](../src/fourthgraph/workflow/project_contract.py)

功能 Profile 选择本地理解的项目，模板版本固定具体的 Script、布局与 WASM。单次签署候选用精确交易字节绑定。模板字节升级要保留旧包以花费旧 UTXO。多步流程逐笔引用已构造并验证的父输出。PELS 归属标准库模板族。此处的 `pels-counter` 实例选用单输入、单后继、固定费用及保留代码的 `advance` 路径，计数按模 2³² 递增。R1 包支持 v0.6.0 的 `ordinary-all` 路径，MESA 签名槽对签后逆元的支持仍待单独评审。

R1 与计数示例包使用 BIP143 ALL（`0x41`）。中性结算项目包使用同一把锁验收 BIP143 ALL 和 Chronicle OTDA ALL（`0x61`）。清单按路径绑定有效 `scriptCode`、见证布局、已认证字段和适用链规则。宿主按请求的获准路径重算原像。结算夹具使用编译器的交易绑定见证，R1 则验收宿主签名。独立验证会拒绝错父交易、错路径、变更覆盖和激活前 OTDA。

```sh
export PYTHONPATH=src:.
python3 tools/build_project_contract.py workflow-examples workspace/settlement --verify
approval="$(sha256sum workspace/settlement/manifest.json | cut -d' ' -f1)"
python3 tools/verify_project_contract.py workspace/settlement/manifest.json \
  --approved-sha256 "$approval" --replay workspace/settlement/receipt.json \
  --output workspace/settlement/replay.json
```

### 夹具可以追加错误输入

每个项目在 `contract/cases.json` 中指定 `id`、`entry`、对固定请求的 `patch` 和 `expect`。期望可以引用独立计算的 `$prepared` 和 `$expected_unlock`。下面是 R1 真实用例，验证拒绝发生在宿主签名之前。

```json
{"id":"wrong-owner-before-sign","entry":"host_spend",
 "patch":{"pubkey":"$other_key"},
 "expect":{"status":"NotOwned","signer_calls":0}}
```

返回错误时还检查响应不含待签材料和解锁脚本。既有用例覆盖三入口的正常返回、缺少前序、输入类型错误、未知模板或路径、错误公钥、缺签、已覆盖输出变化和错误后继。`pels-counter` 分别运行两个状态阶段，第二步使用第一步实际组装的交易作为父交易。新增同类用例只需扩充表并重建本地包，新 manifest 显式绑定更新后的夹具摘要。[R1 用例](../projects/p2pkh-r1/contract/cases.json) · [计数实例用例](../projects/pels-counter/contract/cases.json)

<a name="preimage-constructor"></a>

## 预映像构造器选择

WASM 项目的 `prepare_spend` 依据已批准的交易、真实上一输出和已执行的签名路径计算完整预映像，把原始字节及 SHA256d 交给宿主。需要钱包授权的路径把该摘要交给签名器。PELS 使用完整预映像绑定当前输入。

消费完整预映像栈项的锁，可以用 `4thgraph preimage-constructor request.json` 单独编译压栈部分。请求包含线格式的 `parent_hex`、`transaction_hex`、`input_index`、整数 `sighash`、批准路径的 `script_code_hex`，以及可信链上下文中的 `chronicle_active`。可选 `templates` 每项提供 `script_hex` 和按顺序列出的 `fields`，字段使用字节偏移 `offset` 和长度 `length`。需要伴随路径时提供批准的 `companion_code_hex`。构造器后续解锁脚本的字节数由 `witness_tail_bytes` 计入。

把 WASM 的 `prepare_spend` 结果放在 `prepared` 中，编译器会核对交易哈希、outpoint、输入索引、sighash、原像和摘要。每个候选都要执行并在主栈留下由原始字节组成的完整预映像，备用栈须为空。功能构造器适用于 Chronicle 已激活的版本 2 OTDA ALL 和有同索引输出的 SINGLE。编译器按包含 CompactSize 的解锁脚本字段长度选出最短程序，报告 `program_hex` 和候选记录。可用 `mode: "literal"` 锁定原样对照，用 `max_payload_bytes` 限制构造器的实测栈载荷。当前由编译器和 Schnorr 钱包选构造器，WASM 仍执行标准准备接口计算原像和摘要。接收打包上下文的路径用该路径声明的编码器。[编译入口](../src/fourthgraph/workflow/preimage_constructor.py) · [双引擎交易矩阵](../projects/p2pkh-schnorr/experiments/high-level/constructor-matrix.json)
