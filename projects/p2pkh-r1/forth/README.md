# P2PKH-R1 Forth 构建与复放

[项目主页与实测结果](../README.zh-CN.md#实测结果) · [版本索引](../versions/index.json) · [历史基准](history.md)

`msm.fth` 用显式的 P‑256 双标量乘法表达窗口计算。编译器扫描固定生成元、标量范围和曲线点校验，比较各构造的实际锁与付款字节数，并逐字节核对 OTDA 重建。

`compare --candidate v0.6.0` 直接读取并核对冻结的锁和 OTDA 重建程序，占用一个本地候选名额和一个付款复放名额。传入构造名时从 Forth 编译。v0.6.0 和 v0.7.0 使用同一份两进两出夹具。 [v0.6.0 清单](../versions/v0.6.0/manifest.json) · [v0.7.0 清单](../versions/v0.7.0/manifest.json)

`compare` 默认从冻结的 v0.6.0 出发，优先扫描其后续改写，再从校准构造中选择候选。每个新构造也会扫描一次，候选受 `--budget` 限制。用 `--candidate` 可以直接指定候选。

比较报告为每个候选标记 `origin`，并以 `source_verification` 列出从当前源码编译且通过完整付款复放的候选。显式传入 `--source` 时，至少一个源码候选通过复放才能返回成功。包括预算只够复放冻结对照的情况，命令会写出报告并返回 1。

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
