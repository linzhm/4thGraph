# P2PKH-R1 Forth 实验

[项目主页与实测结果](../../README.zh-CN.md#实测结果) · [历史基准和早期实验](history.md)

`msm.fth` 用显式的 P‑256 双标量乘法表达窗口计算。编译器扫描固定生成元、标量范围和曲线点校验，比较各构造的实际锁与付款字节数，并逐字节核对 OTDA 重建。

从仓库根目录运行。Python 环境需要 [R1 参考依赖](../../reference/requirements.txt)、`ecdsa` 和 [Chronicle chain-gang 固定版本](../../../../tools/requirements-chronicle.txt)。

```sh
project=projects/p2pkh-r1
experiment="$project/experiments/forth"
export PYTHONPATH="src:.:$project/reference"

python "$experiment/msm_experiment.py" scan --candidate split-4
python -m unittest discover -v -s "$experiment" -p 'test_*.py'
bash tools/verify_node.sh --profile raised -- \
  python "$experiment/msm_experiment.py" compare --matrix \
  --output /tmp/r1-comparison.json --evidence /tmp/r1-replay.json
```

报告记录前置扫描依据、各候选的估算与实测、以及每种付款模式的优胜候选。交易证据包含两进两出的付款、两套引擎的判定和改动锁定时间后的拒绝结果。 [已验证的实测数据](results.json)
