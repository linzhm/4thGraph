# Working on 4thGraph

- Keep script projects self-contained under `projects/<name>/`. Put reusable compiler code and Forth libraries under `src/fourthgraph/`, SDK clients under `sdk/`, and developer launchers under `tools/`.
- Keep each project's compiler entry and Forth modules in standalone `.fth` files. Put project Forth modules under `forth/` when grouping them. Host code loads the files, supplies parameters and compiler primitives, and handles signing or replay.
- Start new projects with Copier using the [project scaffold](projects/template/README.md). Edit `manifest.yaml` and regenerate both READMEs when the project introduction or selected release changes.
- Update the affected documentation alongside changes to protocol behavior, public APIs, reproduction commands, or measured results. Use the [documentation templates and maintenance guide](docs/maintaining-docs.md) and run its checks for documentation changes.
- Use the local `workspace/` directories for dependencies, builds and logs. Keep selected artifacts, fixtures and evidence with their version under `projects/<name>/versions/` and link to them from the project and showcase pages.
- Preserve existing script bytes and vectors when moving directories. Update documentation links, SDK module paths and test working directories.
- Prefer a cloud Linux environment or Apple Container for full node validation. Do not start Docker.
- Use local Python/OpenSSL for focused development checks. Use GitHub Actions sparingly as a manual release check, not for the development iteration loop. Keep the project workflows manually triggered to avoid duplicate push/PR runs.
- Keep SM2/SM3/ZA semantics distinct from ECDSA. A local development evaluator is not evidence of consensus compatibility; use the independent BSV Node and chain-gang checks for complete inputs.
- Identify test-only keys/nonces. Keep production signing behind an external signer callback.
