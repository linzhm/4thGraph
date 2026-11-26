# Install 4thGraph

Install the CLI for direct use from a terminal, CI, or a script. Install the Agent Skill in Codex to give it a workflow for authoring Forth, compiling, and checking the result.

## CLI

Use Python 3.11 or later on macOS or Linux. From the root of a BSV Script Lab checkout that includes 4thGraph, run:

```sh
python3 projects/4thgraph/install.py
export PATH="$HOME/.local/bin:$PATH"
4thgraph --version
4thgraph --capabilities
```

This installs `4thgraph` and `4thgraph-report` in `~/.local/bin`. Use `--prefix /path/to/prefix` for a different destination. The commands bundle the compiler modules and their shared Python dependencies, so they can run outside the checkout with Python alone. Run the installer again from the desired revision to upgrade. To uninstall, remove the two commands from the chosen prefix's `bin` directory.

From the repository root, compile the example word and inspect its stack signature, bytecode, and rewrites:

```sh
4thgraph projects/4thgraph/example.fth --entry inc --optimize safe
```

For a transaction plan, pass the Forth source, a JSON mapping of signing roles to compressed secp256k1 public keys, and a 32-byte hexadecimal task ID. For example, set `TASK_ID` to the task ID for the build and run:

```sh
4thgraph contract.fth --mode auto --target both --explain \
  --keys keys.json --task-id "$TASK_ID" > build.json
```

Use `--mode fused` to require a single post-deployment spend, or `--mode split` for independently submitted work steps. Transform a saved replay into a decision report with:

```sh
4thgraph-report replay.json --output-dir decision
```

Use the same checkout revision for the CLI and skill. To generate new replay evidence, use the checkout's [regtest workflow](README.md#复放与编译) with BSV Node and the pinned chain-gang build. Use the checkout for the [circuit and verifier builders](skills/4thgraph/references/circuits-and-verifiers.md) and their backend-specific dependencies.

## Codex Agent Skill

Copy the skill directory into your user skill location from the BSV Script Lab checkout:

```sh
mkdir -p "$HOME/.agents/skills"
cp -R projects/4thgraph/skills/4thgraph "$HOME/.agents/skills/"
```

For one application repository, copy it into that repository's `.agents/skills/` instead. In Codex, invoke `$4thgraph` and provide your Forth source or requirements. For example, ask it to compile the same source in fused and split modes and explain the different transaction boundaries. The skill can use the installed CLI or run the compiler from the BSV Script Lab checkout. If the skill does not appear, reload Codex. [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)

See the [skill workflow](skills/4thgraph/SKILL.md) and [language specification](language.md) for authoring and optimization details.
