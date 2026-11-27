# P2PKH-R1 Forth 构建与复放

[项目主页与实测结果](../README.zh-CN.md#实测结果) · [版本索引](../versions/index.json) · [历史基准](history.md)

## 无窗口的 Forth 参考基线

[普通 R1 入口](r1-baseline.fth) 分别用同一个 256 位倍加词计算 `vQ` 和 `uG`。由 ScriptBuilder 展开固定的位循环。坐标采用现有 `r1-add-points` 的齐次表示，倍点也调用同一个完整点加公式。见证校验、范围、逆元检查和原生交易绑定沿用现有 R1 语义。基线构建省略 `--optimize`。

[带后继断言的 R1 入口](r1-baseline-counter.fth) 调用独立的 [PELS 片段](pels-successor.fth)。调用方只提供从旧状态和输入金额计算后继状态、金额的规则。片段封装 BIP143 ALL 原像解析、单输入检查、CompactSize 和完整输出承诺比对。计数器规定唯一后继、计数加一（u32 回绕）、扣除固定 1,000 sat 并延续同一份合约代码。入口的单个 `OP_CODESEPARATOR` 位于五字节状态之后，原生签名验证覆盖整个合约体。两处检查使用同一个完整原像。

从仓库根目录执行：

```sh
PYTHONPATH=src:. python projects/p2pkh-r1/forth/compile_r1.py --entry r1-baseline-lock
PYTHONPATH=src:. python projects/p2pkh-r1/forth/compile_r1.py \
  --entry r1-baseline-counter --counter-state 0
PYTHONPATH=src:.:projects/p2pkh-r1/forth:projects/p2pkh-r1/reference \
  bash tools/verify_node.sh -- python -m unittest test_r1_baseline test_compile_r1 test_msm
```

前两条命令输出锁十六进制、字节数和源码依赖摘要。测试用合成父输出验证 BIP143、OTDA、无配对 SINGLE、连续计数及重新签名的错误后继。结果覆盖脚本验证。两种锁都是实验参考入口，发布钱包模板继续使用版本清单。

`msm.fth` 用显式的 P‑256 双标量乘法表达窗口计算。编译器扫描固定生成元、标量范围和曲线点校验，比较各构造的实际锁与付款字节数，并逐字节核对 OTDA 重建。

`compare --candidate v0.6.0` 直接读取并核对冻结的锁和 OTDA 重建程序，占用一个本地候选名额和一个付款复放名额。传入构造名时从 Forth 编译。v0.6.0 和 v0.7.0 使用同一份两进两出夹具。 [v0.6.0 清单](../versions/v0.6.0/manifest.json) · [v0.7.0 清单](../versions/v0.7.0/manifest.json)

`compare` 默认从冻结的 v0.6.0 出发，优先扫描其后续改写，再从校准构造中选择候选。每个新构造也会扫描一次，候选受 `--budget` 限制。用 `--candidate` 可以直接指定候选。

比较报告为每个候选标记 `origin`，并以 `source_verification` 列出从当前源码编译且通过完整付款复放的候选。预检和优化构建的 `REQUIRE` 依赖摘要必须一致，摘要变化时会拒绝该候选并列出变化的依赖。显式传入 `--source` 时，至少一个源码候选通过复放才能返回成功。包括预算只够复放冻结对照的情况，命令会写出报告并返回 1。

从仓库根目录运行。Python 环境需要 [R1 参考依赖](../reference/requirements.txt)、`ecdsa` 和 [Chronicle chain-gang 固定版本](../../../tools/requirements-chronicle.txt)。

```sh
project=projects/p2pkh-r1
forth="$project/forth"
export PYTHONPATH="src:.:$project/reference"

python "$forth/msm_experiment.py" scan --candidate split-5x4-affine-g
python "$forth/msm_experiment.py" build --candidate split-5x4-affine-g-ifdup --output /tmp/r1-build.json
python -m unittest discover -v -s "$forth" -p 'test_*.py'
bash tools/verify_node.sh --profile raised -- \
  python "$forth/msm_experiment.py" compare --workflow explicit --matrix \
  --candidate v0.6.0 --candidate v0.7.0 --budget 2 --full-budget 2 \
  --output /tmp/r1-comparison.json --evidence /tmp/r1-replay.json --markdown /tmp/r1-comparison.md
```

报告记录前置扫描依据、各候选的估算与实测、以及每种付款模式的优胜候选。交易证据包含两进两出的付款、两套引擎的判定和改动锁定时间后的拒绝结果。 [v0.7.0 首轮实测](../versions/v0.7.0/comparison.json)

## 复用比较报告

比较报告的 `schema_version` 为 `2`。候选按名称存入 `candidates`，每项含 `status`，实测指标放在 `measured`，可用的估算放在 `estimated`。运行 `--matrix` 时，候选的验收结果存入 `acceptance`。完整锁复放也使用这一结构，候选的原始交易保存在 `payments`。

`compare --reference PATH` 可读取上一轮 `compare --output` 生成的新版报告，也可使用版本目录中的 `comparison.json`。参考报告中已构建的候选计为已知方案。校准比较已有的实测值，输出记录参考文件的 SHA-256。

```sh
bash tools/verify_node.sh --profile raised -- \
  python "$forth/msm_experiment.py" compare --reference /tmp/r1-comparison.json \
  --output /tmp/r1-next-comparison.json
```
