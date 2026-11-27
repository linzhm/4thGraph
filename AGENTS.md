# Working on 4thGraph

- Keep script projects self-contained under `projects/<name>/`. Put reusable compiler code and Forth libraries under `src/fourthgraph/`, SDK clients under `sdk/`, and developer launchers under `tools/`.
- Start new project introductions with `python3 tools/project_readme.py <project>`. Fill the English and Chinese READMEs using the project’s implementation and replay evidence, then run the tool with `--check`. See [project README instructions](projects/README.md#project-readme-template).
- Use the local `workspace/` directories for dependencies, builds and logs. Keep selected artifacts, fixtures and evidence with their version under `projects/<name>/versions/` and link to them from the project and showcase pages.
- Preserve existing script bytes and vectors when moving directories. Update documentation links, SDK module paths and test working directories.
- Prefer a cloud Linux environment or Apple Container for full node validation. Do not start Docker.
- Use local Python/OpenSSL for focused development checks. Use GitHub Actions sparingly as a manual release check, not for the development iteration loop. Keep the project workflows manually triggered to avoid duplicate push/PR runs.
- Keep SM2/SM3/ZA semantics distinct from ECDSA. A local development evaluator is not evidence of consensus compatibility; use the independent BSV Node and chain-gang checks for complete inputs.
- Identify test-only keys/nonces. Keep production signing behind an external signer callback.
