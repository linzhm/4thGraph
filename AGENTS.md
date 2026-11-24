# Working on BSV Script Lab

- Keep each script project self-contained under `projects/<name>/`; put only reusable infrastructure under `shared/`.
- Preserve existing script bytes and vectors when moving directories. Update documentation links, SDK module paths and test working directories.
- Prefer a cloud Linux environment or Apple Container for full node validation. Do not start Docker.
- Use local Python/OpenSSL for focused development checks. Use GitHub Actions sparingly as a manual release check, not for the development iteration loop. Keep the project workflows manually triggered to avoid duplicate push/PR runs.
- Keep SM2/SM3/ZA semantics distinct from ECDSA. A local development evaluator is not evidence of consensus compatibility; use the independent BSV Node and chain-gang checks for complete inputs.
- Identify test-only keys/nonces. Keep production signing behind an external signer callback.
