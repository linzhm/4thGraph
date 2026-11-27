# 4thGraph 新项目脚手架

[English](README.md) · [项目目录](../README.zh-CN.md)

## 创建项目

在仓库根目录为 Copier 和清单校验器创建文档工具环境。

```sh
python3 -m venv workspace/docs
. workspace/docs/bin/activate
python3 -m pip install -r tools/requirements-docs.txt
```

用 Copier 命令创建新项目。

```sh
copier copy --defaults --data-file projects/template/manifest.example.yaml \
  -d title_en="My project" -d title_zh="我的项目" \
  projects/template projects/my-project
```

命令创建一个新项目目录，生成项目介绍清单和双语 README 草稿，并建立实现、文档和版本归档目录。

```text
projects/my-project/
├── manifest.yaml
├── README.md
├── README.zh-CN.md
├── docs/
├── reference/
└── versions/
```

| 路径 | 内容 |
| --- | --- |
| `manifest.yaml` | 双语简介、公开入口、算法、复现和适用的实测章节。两份 README 都由工具生成。 |
| `docs/` | 协议与开发者文档。协议用 `spec.en.md` 和 `spec.zh-CN.md`，有钱包接入时可添加 `sdk.en.md` 和 `sdk.zh-CN.md`。 |
| `reference/` | 项目的构建、参考实现和复放入口。共用工具链代码放在 `src/fourthgraph/`。 |
| `versions/` | 首个基线选定后，在这里提交版本目录及归档产物。 |
| `workspace/` | 本地依赖、构建和日志。运行 `bash tools/setup-workspaces.sh` 创建。 |

[项目清单 Schema](manifest.schema.json) · [起始清单](manifest.example.yaml) · [Schnorr 示例](../p2pkh-schnorr/manifest.yaml)

## 归档首个版本

构建并复放实现。选定首个基线后，参考示例填写 `versions/index.json` 和 `versions/v0.1.0/manifest.json`。实际选定的版本须在目录名、索引和清单中一致。[版本索引示例](versions/index.example.json) · [版本清单示例](versions/manifest.example.json)

版本清单的产物、测试夹具和实测证据路径相对版本目录。`integration` 指向项目内已有的说明文档。填写可在仓库根目录执行的实际构建和验证命令，开发过程中的临时文件留在 `workspace/`。

填好项目清单并选定基线后，重新生成两份 README。发布前检查生成结果和仓库布局。

```sh
python3 tools/project_readme.py my-project --write
python3 tools/project_readme.py my-project --check
PYTHONPATH=src:. python3 -m unittest tests.test_layout tests.test_project_docs
```

已有项目可从示例起草自己的 `manifest.yaml`。README 命令先校验清单并读取当前版本，再调用 Copier。用 `--all --check` 核对所有已采用项目清单的 README。[字段说明](../README.zh-CN.md#项目-readme-模板) · [文档模板和维护约定](../../docs/maintaining-docs.zh-CN.md)
