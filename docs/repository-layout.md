# 4thGraph repository layout

[Documentation index](README.md) · [Project index](../projects/README.md) · [Wallet SDK](../sdk/README.md)

```text
4thGraph/
├── .gitignore                    # Local workspaces and generated files
├── AGENTS.md
├── LICENSE
├── README.md / README.zh-CN.md
├── .github/workflows/            # Manual project acceptance jobs
├── docs/
│   ├── README.md / README.zh-CN.md
│   ├── language/
│   │   ├── README.md             # 4thGraph SDL documentation index
│   │   ├── specification.md
│   │   ├── syntax.md
│   │   └── stdlib.md
│   ├── install.md
│   ├── toolchain.md
│   ├── groth16-bls12-381.md
│   ├── infrastructure.md
│   ├── benchmark.md
│   ├── benchmark.zh-CN.md
│   ├── chronicle-regression.md
│   └── repository-layout.md
├── projects/
│   ├── README.md / README.zh-CN.md
│   ├── lamport-ots/
│   ├── ml-dsa/
│   ├── p2pk-p2pkh-baseline/
│   ├── p2pkh-r1/
│   ├── p2pkh-r1-deferred/
│   ├── p2pkh-schnorr/
│   ├── p2pkh-sm2/
│   ├── pels-counter/
│   ├── proof-counter/
│   ├── workflow-examples/
│   └── wots-plus/
├── sdk/                          # Go, Python, Rust and TypeScript adapters
│   ├── README.md / README.zh-CN.md
│   └── docs/                     # Integration guide and API reference
├── showcase/                     # Evidence and reproduction links
├── skills/4thgraph/
│   ├── SKILL.md
│   └── references/
├── src/fourthgraph/
│   ├── benchmark/                # Measurement drivers
│   ├── bsv/                      # Script and transaction primitives
│   ├── compiler/                 # Forth parsing, checking and optimization
│   ├── replay/                   # Funded regtest and evidence generation
│   ├── stdlib/                   # Bundled Forth words and interface catalog
│   ├── verification/             # Script, circuits and proof backends
│   ├── workflow/                 # Transaction state and workflow frontends
│   └── reporting.py
├── tests/                        # Toolchain, packaging and layout regression tests
├── tools/                        # Setup, installation and node launchers
├── workspace/                    # Local toolchain builds, caches and logs
└── pyproject.toml                # Python package and four installed commands
```

[Projects](../projects/README.md) are the runnable examples. They keep their own reference code, templates, experiments and verified results. `bash tools/setup-workspaces.sh` creates local workspaces at the root and inside each project. It is safe to rerun. Git ignores the directories.

The [SDL documentation](language/README.md) describes code shipped with 4thGraph. The [Codex skill](../skills/4thgraph/SKILL.md) has its own installation and uses the toolchain through documented inputs and commands. The [showcase](../showcase/README.md) links measurements to the project that produced them.
