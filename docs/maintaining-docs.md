# Maintaining 4thGraph documentation

[简体中文](maintaining-docs.zh-CN.md) · [Documentation index](README.md) · [Project scaffold](../projects/template/README.md)

Update the page that already owns the topic. Put shared language and toolchain guidance under `docs/`, and project-specific protocol, integration, and replay guides under `projects/<name>/docs/`. Link version-specific evidence from the release directory. Keep stable filenames and anchors when moving a page.

| Page | Source of truth | Template |
| --- | --- | --- |
| Project overview | Project `manifest.yaml` and current release manifest | [Copier project template](../projects/template/README.md) |
| Protocol or wire format | Implementation, specification and acceptance tests | [English](templates/spec.en.md.in) · [简体中文](templates/spec.zh-CN.md.in) |
| SDK or integration | Public entry points and an executable example | [English](templates/sdk.en.md.in) · [简体中文](templates/sdk.zh-CN.md.in) |
| Verification or reproduction | Runnable commands, pinned fixtures and recorded results | [English](templates/verification.en.md.in) · [简体中文](templates/verification.zh-CN.md.in) |

For a new project guide, copy the relevant templates without the `.in` suffix. Fill the prompts, link the implementation or evidence, and cross-link the language pair. Add the entry to the closest existing index. For an existing guide, keep its established names and anchors.

## Update docs with the change

| Change | Pages and evidence to update |
| --- | --- |
| Protocol, encoding or rejection behavior | Update the affected protocol pages in both languages and link the corresponding source or acceptance tests. |
| API, dependency or command | Update the integration and replay examples that call it. Run the edited commands from the stated working directory. |
| Version, artifact or measured result | Update the release index and evidence, then edit the project manifest and regenerate both README files. Include the measured version, transaction shape or other relevant inputs, and units. |
| Page move or rename | Update inbound links and language links in the same change. Preserve anchors that other pages depend on. |

Keep numerical results tied to the recorded replay. Use the same version, flags, and evidence links across both languages. Record which commands ran and which cases were verified when proposing the change.

After editing a shared Copier template, refresh the generated README pairs with `python3 tools/project_readme.py --all --write`.

## Check before review

In the documentation environment, run:

```sh
python3 tools/project_readme.py --all --check
PYTHONPATH=src:. python3 -m unittest tests.test_layout tests.test_project_docs
```

These local checks cover generated README drift, missing project manifests, local links, unfinished template prompts, and the language links for the standard project guides. Review technical claims and example output against the linked source or replay. [Install the documentation tools](../projects/template/README.md)

The README update workflow triggers on pushes that change a project YAML manifest, version index, or release manifest. It regenerates the affected projects when their current inputs change and pushes a commit containing the refreshed READMEs if any changed. [README update workflow](../.github/workflows/documentation.yml)
