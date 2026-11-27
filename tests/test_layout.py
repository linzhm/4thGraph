"""Guard project migration, canonical R1 bytes, and local documentation links."""
import hashlib
import json
import os
from pathlib import Path
import re
from shutil import copy2, copytree, which
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from fourthgraph.bsv.script import assemble
from sdk.python.bridge import WALLET_PROJECTS

ROOT=Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = ('.github', 'docs', 'projects', 'sdk', 'showcase', 'skills')
BUILD_DIRECTORIES = {'.git', '.venv', '__pycache__', 'node_modules', 'target', 'workspace'}


def tracked_files(root, pathspec):
    tracked = subprocess.run(
        ['git', 'ls-files', '-z', '--', pathspec], cwd=root, check=True, capture_output=True,
    ).stdout
    return (root / os.fsdecode(name) for name in tracked.split(b'\0') if name)


def markdown_files(root):
    if (root / '.git').exists() and which('git'):
        yield from (path for path in tracked_files(root, '*.md') if path.is_file())
        return

    # Source exports have no index. Walk the repository's documentation roots
    # and prune local dependency and build directories before reading files.
    yield from (path for path in root.glob('*.md') if path.is_file())
    for directory in SOURCE_DIRECTORIES:
        for current, dirs, files in os.walk(root / directory):
            dirs[:] = sorted(set(dirs) - BUILD_DIRECTORIES)
            for name in sorted(files):
                if name.endswith('.md'):
                    yield Path(current) / name


def project_directories(root):
    projects = root / "projects"
    if (root / ".git").exists() and which("git"):
        candidates = {path.parent.parent for path in projects.glob("*/versions/index.json")}
        for path in tracked_files(root, "projects"):
            relative = path.relative_to(projects)
            if len(relative.parts) > 1:
                candidates.add(projects / relative.parts[0])
    else:
        candidates = {path for path in projects.iterdir() if path.is_dir()}
    return sorted(candidates - {projects / "template"})


def write_markdown(root, relative, target):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'[Local reference]({target})\n', encoding='utf-8')
    return path


def readme_tool_fixture(root):
    copytree(ROOT / "projects/template", root / "projects/template")
    tool = root / "tools/project_readme.py"
    tool.parent.mkdir()
    copy2(ROOT / "tools/project_readme.py", tool)
    return tool


class LayoutTests(unittest.TestCase):
    def test_r1_canonical_bytes_unchanged(self):
        project=ROOT/'projects/p2pkh-r1'
        layout=json.loads((project/'versions/v0.1.0/layout.json').read_text())
        raw=bytes.fromhex((project/'versions/v0.1.0/template.hex').read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'b3acd6b92a23120bd24432ada2b1cac013fe06381d7ea96ac6c5a73c493f4287')
        for vector in layout['vectors']:
            owner=bytes.fromhex(vector['owner_hash160']); rebuilt=assemble(project/'reference/asm',owner)
            self.assertEqual(hashlib.sha256(rebuilt).hexdigest(),vector['script_sha256'])
            self.assertEqual(rebuilt,raw[:208]+owner+raw[228:])

    def test_project_resources_and_local_links(self):
        for name in ('p2pkh-r1','p2pkh-r1-deferred','p2pkh-sm2'):
            for child in ('README.md','docs','reference','versions'):
                self.assertTrue((ROOT/'projects'/name/child).exists())
        self.check_local_links(ROOT)

    def test_project_version_catalogs(self):
        for project in project_directories(ROOT):
            with self.subTest(project=project.name):
                versions = project / "versions"
                index = json.loads((versions / "index.json").read_text())
                self.assertEqual(index["schema_version"], 1)
                ordered = index["versions"]
                self.assertTrue(all(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) for version in ordered))
                self.assertEqual(ordered, sorted(set(ordered), key=lambda version: tuple(map(int, version.split(".")))))
                current = index["current"]
                if "next" in index:
                    self.assertEqual([current, index["next"]], ordered[-2:])
                else:
                    self.assertEqual(current, ordered[-1])
                if "sdk_default" in index:
                    self.assertIn(index["sdk_default"], ordered[:ordered.index(current) + 1])
                self.assertEqual({path.name for path in versions.iterdir() if path.is_dir()},
                                 {f"v{version}" for version in ordered})
                previous = None
                earlier_files = set()
                for version in ordered:
                    directory = versions / f"v{version}"
                    manifest = json.loads((directory / "manifest.json").read_text())
                    self.assertEqual((manifest["version"], manifest["previous"]), (version, previous))
                    listed = manifest["artifacts"] + manifest["fixtures"] + manifest["evidence"]
                    actual = {file.relative_to(directory).as_posix() for file in directory.rglob("*") if file.is_file()}
                    self.assertEqual(sorted(listed), sorted(actual - {"manifest.json"}))
                    self.assertTrue(set(manifest.get("shared_data", [])) <= earlier_files)
                    for dependency, required in manifest.get("requires", {}).items():
                        pinned = ROOT / "projects" / dependency / "versions" / f"v{required}" / "manifest.json"
                        self.assertTrue(pinned.is_file(), f"{project.name} v{version} needs {dependency} v{required}")
                    self.assertTrue((project / manifest["integration"].split("#", 1)[0]).is_file())
                    self.assertTrue(manifest["build"])
                    self.assertTrue(manifest["verify"])
                    earlier_files.update(f"versions/v{version}/{name}" for name in listed)
                    previous = version

    def test_sdk_quickstarts_are_reachable(self):
        for filename, language in (("README.md", "en"), ("README.zh-CN.md", "zh-CN")):
            overview = (ROOT / filename).read_text(encoding="utf-8")
            shared_guide = (ROOT / "sdk" / filename).read_text(encoding="utf-8")
            self.assertIn(f"](sdk/{filename}#quickstart)", overview)
            self.assertIn('<a name="quickstart"></a>', shared_guide)
            for name in sorted(WALLET_PROJECTS):
                with self.subTest(project=name, language=language):
                    project = ROOT / "projects" / name
                    guide = f"docs/sdk.{language}.md"
                    self.assertIn(f"]({guide}#quickstart)", (project / filename).read_text(encoding="utf-8"))
                    self.assertIn(f"](../projects/{name}/{guide}#quickstart)", shared_guide)
                    self.assertIn('<a name="quickstart"></a>', (project / guide).read_text(encoding="utf-8"))

    def test_readme_scaffold_fills_missing_files_without_overwriting(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tool = readme_tool_fixture(root)
            project = root / "projects/demo"
            english = project / "README.md"
            chinese = project / "README.zh-CN.md"

            def run(*args):
                return subprocess.run([sys.executable, tool, "demo", *args],
                                      cwd=root, capture_output=True, text=True)

            generated = run("--title", "Example", "--title-zh", "示例")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertTrue(english.read_text(encoding="utf-8").startswith("# Example\n"))
            self.assertTrue(chinese.read_text(encoding="utf-8").startswith("# 示例\n"))
            self.assertNotIn("versions/index.json", english.read_text(encoding="utf-8"))
            self.assertIn("still contains template prompts", run("--check").stderr)

            edited = "# Example\n\nPublished content.\n"
            english.write_text(edited, encoding="utf-8")
            chinese.unlink()
            version = project / "versions/v1.0.0"
            version.mkdir(parents=True)
            (version.parent / "index.json").write_text('{"current":"1.0.0"}', encoding="utf-8")
            (version / "manifest.json").write_text('{"build":"make build","verify":"make check"}', encoding="utf-8")
            (version / "measurements.json").touch()
            docs = project / "docs"
            docs.mkdir()
            (docs / "sdk.zh-CN.md").write_text('<a name="quickstart"></a>\n', encoding="utf-8")
            rebuilt = run("--title-zh", "示例")
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
            self.assertEqual(english.read_text(encoding="utf-8"), edited)
            result = chinese.read_text(encoding="utf-8")
            self.assertIn("versions/index.json", result)
            self.assertIn("versions/v1.0.0/measurements.json", result)
            self.assertIn("docs/sdk.zh-CN.md#quickstart", result)
            self.assertIn("make build\nmake check", result)
            chinese.write_text("# 示例\n\n已填写。\n", encoding="utf-8")
            checked = run("--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_readme_manifest_regenerates_both_languages_and_checks_drift(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tool = readme_tool_fixture(root)
            project = root / "projects/demo"
            manifest = project / "manifest.json"

            def run(*args):
                return subprocess.run([sys.executable, tool, "demo", *args],
                                      cwd=root, capture_output=True, text=True)

            initialized = run("--init", "--title", "Example", "--title-zh", "示例")
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            self.assertFalse((project / "README.md").exists())
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(data["title"], {"en": "Example", "zh-CN": "示例"})
            self.assertEqual((project / data["$schema"]).resolve(),
                             root.resolve() / "projects/template/manifest.schema.json")
            reserved = subprocess.run([sys.executable, tool, "template", "--init"],
                                      cwd=root, capture_output=True, text=True)
            self.assertNotEqual(reserved.returncode, 0)
            self.assertFalse((root / "projects/template/manifest.json").exists())

            data["summary"] = {"en": "Overview.", "zh-CN": "项目介绍。"}
            data["entry_points"] = []
            data["sections"] = {
                "algorithm": {"en": ["Compute the result."], "zh-CN": ["计算结果。"]},
                "reproduction": {"en": ["Run the tests."], "zh-CN": ["运行测试。"]},
            }
            encoded = json.dumps(data, ensure_ascii=False)
            manifest.write_text(encoded, encoding="utf-8")
            self.assertNotEqual(run("--init").returncode, 0)
            self.assertEqual(manifest.read_text(encoding="utf-8"), encoded)
            release = project / "versions/v1.0.0"
            release.mkdir(parents=True)
            (release.parent / "index.json").write_text('{"current":"1.0.0"}', encoding="utf-8")
            (release / "manifest.json").write_text('{"build":"make build","verify":"make verify"}',
                                                  encoding="utf-8")
            generated = run("--write")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            english = project / "README.md"
            chinese = project / "README.zh-CN.md"
            first = english.read_text(encoding="utf-8")
            self.assertIn("# Example v1.0.0", first)
            self.assertIn("Compute the result.", first)
            self.assertNotIn("## Script sizes", first)
            self.assertIn("# 示例 v1.0.0", chinese.read_text(encoding="utf-8"))
            self.assertIn("make build\nmake verify", first)
            english.write_text(first + "\nDrift.\n", encoding="utf-8")
            self.assertIn("differs from its manifest", run("--check").stderr)
            self.assertEqual(run("--write").returncode, 0)
            self.assertEqual(english.read_text(encoding="utf-8"), first)
            checked = run("--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

            data["summary"].pop("zh-CN")
            manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            invalid = run("--write")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("summary is missing zh-CN", invalid.stderr)
            self.assertEqual(english.read_text(encoding="utf-8"), first)

    def test_generated_project_readmes_match_their_manifests(self):
        tool = ROOT / "tools/project_readme.py"
        for project in project_directories(ROOT):
            if not (project / "manifest.json").is_file():
                continue
            with self.subTest(project=project.name):
                checked = subprocess.run([sys.executable, tool, project.name, "--check"],
                                         cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_new_project_scaffold_creates_a_draft_without_claiming_a_version(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tool = readme_tool_fixture(root)
            command = [sys.executable, tool, "demo", "--scaffold", "--title", "Demo", "--title-zh", "示例"]
            created = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            project = root / "projects/demo"
            self.assertEqual({path.name for path in project.iterdir()},
                             {"manifest.json", "README.md", "README.zh-CN.md", "docs", "reference", "versions"})
            for name in ("docs", "reference", "versions"):
                self.assertTrue((project / name).is_dir())
            self.assertFalse((project / "versions/index.json").exists())
            self.assertIn("# Demo", (project / "README.md").read_text(encoding="utf-8"))
            self.assertIn("# 示例", (project / "README.zh-CN.md").read_text(encoding="utf-8"))
            project_readme = project / "README.md"
            project_readme.write_text("Existing project content.\n", encoding="utf-8")
            duplicate = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(project_readme.read_text(encoding="utf-8"), "Existing project content.\n")

    def check_local_links(self, root):
        for path in markdown_files(root):
            for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
                if ':' in target or target.startswith('#'): continue
                target=target.split('#')[0]
                self.assertTrue((path.parent/target).exists(),f'{path.relative_to(root)} -> {target}')

    @unittest.skipUnless(which('git'), 'requires Git for the checkout fixture')
    def test_checkout_checks_tracked_markdown_only(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True, capture_output=True)
            (root / '.gitignore').write_text('.venv/\nnode_modules/\ntarget/\n', encoding='utf-8')
            tracked = write_markdown(root, 'Tracked guide 文档.md', '.gitignore')
            subprocess.run(['git', 'add', '--', tracked.name], cwd=root, check=True, capture_output=True)
            write_markdown(root, '.venv/lib/dependency/README.md', 'missing.md')
            write_markdown(root, 'projects/demo/sdk/node_modules/dependency/README.md', 'missing.md')
            write_markdown(root, 'projects/demo/target/README.md', 'missing.md')
            write_markdown(root, 'local-archive/README.md', 'missing.md')

            self.check_local_links(root)
            write_markdown(root, tracked.name, 'missing.md')
            with self.assertRaisesRegex(AssertionError, 'Tracked guide 文档.md -> missing.md'):
                self.check_local_links(root)

    def test_source_export_checks_project_docs_and_skips_build_directories(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').touch()
            tracked = 'projects/demo/docs/guide.md'
            write_markdown(root, tracked, '../../../README.md')
            write_markdown(root, '.venv/lib/dependency/README.md', 'missing.md')
            write_markdown(root, 'projects/demo/sdk/node_modules/dependency/README.md', 'missing.md')
            write_markdown(root, 'projects/demo/target/README.md', 'missing.md')
            write_markdown(root, 'local-archive/README.md', 'missing.md')

            self.check_local_links(root)
            write_markdown(root, tracked, 'missing.md')
            with self.assertRaisesRegex(AssertionError, 'guide.md -> missing.md'):
                self.check_local_links(root)


if __name__=='__main__': unittest.main()
