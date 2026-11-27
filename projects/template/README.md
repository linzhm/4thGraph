# 4thGraph project scaffold

[简体中文](README.zh-CN.md) · [Project index](../README.md)

## Create a project

From the repository root, install Copier and the manifest validator in a documentation environment.

```sh
python3 -m venv workspace/docs
. workspace/docs/bin/activate
python3 -m pip install -r tools/requirements-docs.txt
```

Create a new project with the Copier CLI.

```sh
copier copy --defaults --data-file projects/template/manifest.example.yaml \
  -d title_en="My project" -d title_zh="我的项目" \
  projects/template projects/my-project
```

The command creates a fresh project directory with the introduction manifest and draft READMEs. It creates the three working directories for implementation, documentation, and versioned evidence.

```text
projects/my-project/
├── manifest.yaml
├── README.md
├── README.zh-CN.md
├── docs/
├── reference/
└── versions/
```

| Path | Contents |
| --- | --- |
| `manifest.yaml` | Bilingual overview, public entry points, algorithm, reproduction and applicable measurements. The generator owns both READMEs. |
| `docs/` | Protocol and developer guides. Use `spec.en.md` and `spec.zh-CN.md` for the protocol. Projects with a wallet integration can add `sdk.en.md` and `sdk.zh-CN.md`. |
| `reference/` | Project-specific build, reference implementation, and replay entry points. Shared toolchain code belongs under `src/fourthgraph/`. |
| `versions/` | Catalog and immutable baseline artifacts once a version is selected. |
| `workspace/` | Local builds, dependencies and logs. Run `bash tools/setup-workspaces.sh` to create it. |

[Project manifest schema](manifest.schema.json) · [Starter manifest](manifest.example.yaml) · [Schnorr example](../p2pkh-schnorr/manifest.yaml)

## Record the first version

Build and replay the implementation. When selecting the first baseline, populate `versions/index.json` and `versions/v0.1.0/manifest.json` from these examples. Use the selected version consistently in the directory name, index and manifest. [Catalog example](versions/index.example.json) · [Release manifest example](versions/manifest.example.json)

The release manifest lists paths to the retained artifacts, fixtures and evidence relative to the version directory. Set `integration` to an existing guide relative to the project. Supply actual `build` and `verify` commands that run from the repository root. Keep working data under `workspace/`.

Regenerate the READMEs after filling the project manifest and selecting the baseline. Check the README pair and the repository layout before publishing.

```sh
python3 tools/project_readme.py my-project --write
python3 tools/project_readme.py my-project --check
PYTHONPATH=src:. python3 -m unittest tests.test_layout tests.test_project_docs
```

For an existing project, start with the example `manifest.yaml`. The README command validates the manifest, reads the selected release metadata, and calls Copier. Use `--all --check` to check the README pairs for all projects with a manifest. [Manifest fields](../README.md#project-readme-template) · [Documentation templates and maintenance](../../docs/maintaining-docs.md)
