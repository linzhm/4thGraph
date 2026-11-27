# 维护 4thGraph 文档

[English](maintaining-docs.md) · [文档索引](README.zh-CN.md) · [项目脚手架](../projects/template/README.zh-CN.md)

优先更新已有的主题页。共用语言和工具链说明放在 `docs/`，项目的协议、接入和复放说明放在 `projects/<name>/docs/`，版本专属证据链接到对应归档。移动文档时保留稳定文件名或锚点，并更新已有引用。

| 页面 | 内容来源 | 模板 |
| --- | --- | --- |
| 项目介绍 | 项目 `manifest.yaml` 和当前版本清单 | [Copier 项目模板](../projects/template/README.zh-CN.md) |
| 协议或线格式 | 实现、规范及验收测试 | [中文](templates/spec.zh-CN.md.in) · [English](templates/spec.en.md.in) |
| SDK 或接入 | 公开接口及可执行示例 | [中文](templates/sdk.zh-CN.md.in) · [English](templates/sdk.en.md.in) |
| 验证或复现 | 可运行命令、固定夹具及结果记录 | [中文](templates/verification.zh-CN.md.in) · [English](templates/verification.en.md.in) |

新增项目说明时，把对应模板复制到项目的 `docs/`，去掉文件名末尾的 `.in`。替换提示内容，链接实现或证据，给中英文页面加互链，再把入口加入已有索引。编辑现有说明时沿用它的文件名和锚点。

## 哪些变化需要同步文档

| 改动 | 要同步的文档和证据 |
| --- | --- |
| 协议、编码或拒绝条件 | 更新两种语言的相关协议页，链接对应实现或验收测试。 |
| API、依赖或命令 | 更新调用它的接入和复放示例，从文档所写的工作目录运行修改后的命令。 |
| 版本、产物或实测结果 | 更新版本索引和证据，然后更新项目清单并重生成双语 README。注明实测版本、交易形状或其他相关输入和单位。 |
| 页面移动或改名 | 同一改动中更新引用和语言互链，保留其他页面使用的锚点。 |

测量数字要能追溯到复放记录。两种语言使用相同的版本、参数和证据链接。提交改动时说明实际运行了哪些命令、核验了哪些用例。

改动共享 Copier 模板后，用 `python3 tools/project_readme.py --all --write` 更新各项目的中英文 README。

## 提交前检查

在文档工具环境里运行：

```sh
python3 tools/project_readme.py --all --check
PYTHONPATH=src:. python3 -m unittest tests.test_layout tests.test_project_docs
```

这些本地检查覆盖 README 生成差异、缺失的项目清单、本地链接、未填模板提示和标准项目说明的语言互链。技术表述和示例输出仍需与链接的实现或复放结果核对。[安装文档工具](../projects/template/README.zh-CN.md)

推送改动项目 YAML 清单、版本索引或版本清单时，会触发 README 更新工作流。工作流只重生成当前输入有变化的项目，生成文件有改动时提交回当前分支。[README 更新工作流](../.github/workflows/documentation.yml)
