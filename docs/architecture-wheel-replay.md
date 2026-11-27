# Combined wheel replay · 组合 wheel 复跑

[Architecture](architecture.md) · [架构](architecture.zh-CN.md)

This check combines the five review heads below on `main` at `70e65368aec842cc2758e273d5c99cabae2a4936`. The merged source tree is `547d47591fa498b7ed3680bbf8118db83c6b74e8`.

本次验收将下列五个评审提交基于 `main` 的 `70e65368aec842cc2758e273d5c99cabae2a4936` 组合，合并后的源码树为 `547d47591fa498b7ed3680bbf8118db83c6b74e8`。

| Review · 评审 | Commit · 提交 |
| --- | --- |
| [#86](https://github.com/linzhm/4thGraph/pull/86) | `cdf8a83b4950b19c2ea72e1a000524e07c046f86` |
| [#87](https://github.com/linzhm/4thGraph/pull/87) | `e74e7cb594003988612436886dfdb0ac9af6bcca` |
| [#88](https://github.com/linzhm/4thGraph/pull/88) | `a294414d878e45c80c043a31a3ed810daef70fb4` |
| [#89](https://github.com/linzhm/4thGraph/pull/89) | `13d13ea92939705c9440d6ef10fd6e2be04c8481` |
| [#90](https://github.com/linzhm/4thGraph/pull/90) | `619610f615ccd4cf295f09fadd9c295377187d23` |

## Build and replay · 构建与复跑

Run from a full clone of `linzhm/4thGraph` with `origin` pointing to GitHub. Use Bash, Python 3.12 with `venv`, Node.js with WASI preview1, and a Rust/C build toolchain for the pinned `tx-engine` dependency. The commands create a temporary worktree and write reports outside the checkout.

在 `linzhm/4thGraph` 的完整克隆中运行，`origin` 指向 GitHub 仓库。环境需要 Bash、带 `venv` 的 Python 3.12、支持 WASI preview1 的 Node.js，以及用于构建固定版 `tx-engine` 的 Rust/C 工具链。命令使用临时工作树，在源码检出目录之外保存报告。

```bash
(
  set -e
  unset PYTHONPATH
  review_dir=$(mktemp -d)
  heads=(
    cdf8a83b4950b19c2ea72e1a000524e07c046f86
    e74e7cb594003988612436886dfdb0ac9af6bcca
    a294414d878e45c80c043a31a3ed810daef70fb4
    13d13ea92939705c9440d6ef10fd6e2be04c8481
    619610f615ccd4cf295f09fadd9c295377187d23
  )
  git fetch origin "${heads[@]}"
  git worktree add --detach "$review_dir/source" "${heads[0]}"
  git -C "$review_dir/source" -c user.name='Wheel replay' -c user.email='wheel-replay@example.invalid' \
    merge --no-commit --no-ff "${heads[@]:1}"
  test "$(git -C "$review_dir/source" write-tree)" = 547d47591fa498b7ed3680bbf8118db83c6b74e8

  python3.12 -m venv "$review_dir/venv"
  python="$review_dir/venv/bin/python"
  "$python" -m pip wheel --no-deps --wheel-dir "$review_dir/wheel" "$review_dir/source"
  "$python" -m zipfile -l "$review_dir"/wheel/*.whl > "$review_dir/wheel-files.txt"
  "$python" -m pip install --no-deps "$review_dir"/wheel/*.whl
  "$python" -m pip install -r "$review_dir/source/tools/requirements-chronicle.txt"

  cd "$review_dir"
  "$review_dir/venv/bin/4thgraph" experiment run - > bezier.json <<'JSON'
{"fixture":"bezier","axis":"A","plans":[{}, {"passes":["stack"]}],"workers":1,"time_ms":300000}
JSON
  bundle="$review_dir/source/projects/p2pkh-r1/versions/v0.6.0/contract"
  "$python" "$review_dir/source/tools/verify_project_contract.py" "$bundle/manifest.json" \
    --approved-sha256 2dddac4e7a9eb6b2f08a16357c2db78461b6fc0e37b429c8fff29c4b64ef3d97 \
    --replay "$bundle/receipt.json" --chain-only --output r1-replay.json
  printf 'Reports / 报告 %s\n' "$review_dir"
)
```

## Observed results · 实测结果

The `wheel-files.txt` inventory lists `fourthgraph/benchmark/formulas/bezier.fth`, `fourthgraph/workflow/contract_runtime.mjs`, and the PELS entry points in `fourthgraph/stdlib/pels.fth` and `fourthgraph/stdlib/wallet/pels-verify.fth`. R1 used chain-gang 0.13.2 at `74676b9c002c452e7f21a9ed9265f4972bef03f6` for offline Script verification.

`wheel-files.txt` 列出上述 Bézier 夹具、WASI 运行文件和两个 PELS 标准库入口。R1 使用 chain-gang 0.13.2 的 `74676b9c002c452e7f21a9ed9265f4972bef03f6` 提交离线验证 Script。

| Report · 报告 | Case · 用例 | Result · 结果 |
| --- | --- | --- |
| `bezier.json` | Bézier baseline · 基线 | 118 B, 625/625 |
| `bezier.json` | Bézier `stack` | 47 B, 625/625 |
| `r1-replay.json` | R1 v0.6.0 `ordinary-all` | `passed`, 1 spend · 1 笔花费 |
