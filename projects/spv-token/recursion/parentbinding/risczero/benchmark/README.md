# 同一笔 BSV 父交易的 Groth16 与 STARK 基准

输入是独立 BSV Node 已确认的一笔 3,433 字节原生解冻交易，选定唯一的 `vout 0`。两种后端对同一个 32 字节公开摘要出证。它承诺从真实原文算出的 txid、标准 IV 起算的 SHA-256 中间态、已处理长度、规范输出边界和包括该 TxOut 的后缀。固定布局和代币字段检查与现有 `parent-checkpoint-token` 电路对应。此次结论限于单父开口组件。完整 CCTP 付款仍需认证真实父验证器、前序来源关系和本笔守恒。 [原 BSV 入块记录](../../../../fixtures/token-checkpoint-regtest-summary.json) · [Groth16 电路](../../../parentcheckpoint/token.go) · [STARK 程序](src/bin/checkpoint-guest.rs)

| Apple M1 Max 实测 | 每次出证秒数 | 本机验真 | 输出的字节口径 |
|---|---|---:|---:|
| gnark BLS12-381 Groth16，`GOMAXPROCS=4` | 11.31、16.25、17.95 | 1.2–3.4 ms | 已入块配置的证明 push 为 1,077 B |
| RISC Zero 3.1.0 STARK，composite | 13.86、14.91、13.79 | 13.9–15.8 ms | 宿主收据 244,366 B |
| RISC Zero 3.1.0 STARK，succinct | 25.66 | 13.2 ms | 宿主收据 223,290 B |

Groth16 出证用常驻会话中记录的原生计时。冷启动编译、验证及加载已有参数和三次证明总计 307.45 秒，进程峰值 RSS 7.09 GB。STARK 出证的进程计时包括程序执行、出证和收据写盘。composite 峰值约 1.27 GB，succinct 约 2.26 GB。三次 Groth16 中有两次与初版 STARK 试跑部分重叠。两种锁的 BSV 成本应从独立节点花费实测，表内 STARK 收据长度是宿主编码里的字节数。测试拒绝了另一个公开摘要、另一个程序身份和与真实输出布局不符的输出数。 [逐次结果](result.json) · [RISC Zero 3.1.0](https://github.com/risc0/risc0/releases/tag/v3.1.0)

## 复现

从仓库根目录运行。使用常规宿主 Cargo、RISC Zero [3.1.0 Apple Silicon 的 r0vm](https://github.com/risc0/risc0/releases/tag/v3.1.0)及 [RISC-V guest Rust 工具链 r0.1.97.0](https://github.com/risc0/rust/releases/tag/r0.1.97.0)。`CCTP_R0VM` 指向解包后的 `r0vm`，`CCTP_GUEST_RUST` 指向解包后的工具链目录。

```sh
bench=projects/spv-token/recursion/parentbinding/risczero/benchmark
cctp_run=$(mktemp -d)
export PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion
python3 "$bench/prepare.py" "$cctp_run"

CARGO_TARGET_DIR="$cctp_run/host" cargo build --locked --release \
  --manifest-path "$bench/Cargo.toml" --bin checkpoint-image --bin checkpoint-verify
RUSTC="$CCTP_GUEST_RUST/bin/rustc" PATH="$CCTP_GUEST_RUST/bin:$PATH" \
  RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' \
  CARGO_TARGET_DIR="$cctp_run/guest" cargo build --locked --release \
  --manifest-path "$bench/Cargo.toml" --target riscv32im-risc0-zkvm-elf --bin checkpoint-guest
"$cctp_run/host/release/checkpoint-image" \
  "$cctp_run/guest/riscv32im-risc0-zkvm-elf/release/checkpoint-guest" "$cctp_run/image.bin"
"$CCTP_R0VM" --elf "$cctp_run/image.bin" --id > "$cctp_run/image-id.txt"
for kind in composite succinct; do
  /usr/bin/time -l env -u RISC0_DEV_MODE "$CCTP_R0VM" --elf "$cctp_run/image.bin" \
    --initial-input "$cctp_run/parent.bin" --receipt-kind "$kind" --receipt "$cctp_run/$kind.bin"
  "$cctp_run/host/release/checkpoint-verify" "$cctp_run/$kind.bin" \
    "$(cat "$cctp_run/image-id.txt")" "$(cat "$cctp_run/digest.txt")"
done

(cd projects/spv-token/recursion && go build -o "$cctp_run/groth16" ./freeze/cmd)
GOMAXPROCS=4 "$cctp_run/groth16" -mode setup -profile parent-checkpoint-token -dir "$cctp_run/params"
GOMAXPROCS=4 /usr/bin/time -l "$cctp_run/groth16" -mode session \
  -profile parent-checkpoint-token -dir "$cctp_run/params" < "$cctp_run/groth16-input.jsonl"
```

Groth16 的逐次原生计时从输出的 `groth16-proof-*.json` 读取。已有同 profile 测试参数时，可以直接运行会话。STARK 宿主验证同时固定 guest image ID 和预期摘要。单独替换任一值应返回错误。
