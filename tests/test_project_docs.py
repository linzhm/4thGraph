"""Exercise the Copier scaffold and generated documentation checks."""

from importlib.util import find_spec
import json
from pathlib import Path
from shutil import copy2, copytree
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.test_layout import project_directories


ROOT = Path(__file__).resolve().parents[1]
TOOL = "tools/project_readme.py"
DOC_TOOLS = all(find_spec(module) for module in ("copier", "jsonschema", "yaml"))
MANIFEST = {
    "schema_version": 1,
    "title": {"en": "Example", "zh-CN": "示例"},
    "summary": {"en": "Overview.", "zh-CN": "介绍。"},
    "entry_points": [],
    "sections": {
        "algorithm": {"en": ["Compute a result.\n\n```text\nexample\n```"], "zh-CN": ["计算结果。"]},
        "reproduction": {"en": ["Run the tests."], "zh-CN": ["运行测试。"]},
    },
}


def run(root, *args):
    return subprocess.run([sys.executable, *args], cwd=root, capture_output=True, text=True)


def checkout_fixture(root):
    copytree(ROOT / "projects/template", root / "projects/template")
    (root / "tools").mkdir()
    copy2(ROOT / TOOL, root / TOOL)


@unittest.skipUnless(DOC_TOOLS, "install tools/requirements-docs.txt to exercise Copier")
class ProjectDocsTests(unittest.TestCase):
    def test_official_copier_command_bootstraps_project(self):
        from yaml import safe_load

        with TemporaryDirectory() as directory:
            root = Path(directory)
            checkout_fixture(root)
            created = run(root, "-m", "copier", "copy", "--defaults", "--data-file",
                          "projects/template/manifest.example.yaml", "-d", "title_en=Example",
                          "-d", "title_zh=示例", "projects/template", "projects/example")
            self.assertEqual(created.returncode, 0, created.stderr)
            project = root / "projects/example"
            self.assertEqual({path.name for path in project.iterdir()},
                             {"manifest.yaml", "README.md", "README.zh-CN.md", "docs", "reference", "versions"})
            manifest = safe_load((project / "manifest.yaml").read_text(encoding="utf-8"))
            self.assertEqual(manifest["title"], MANIFEST["title"])
            self.assertTrue((project / manifest["$schema"]).is_file())
            self.assertIn("# Example", (project / "README.md").read_text(encoding="utf-8"))
            self.assertIn("# 示例", (project / "README.zh-CN.md").read_text(encoding="utf-8"))
            self.assertFalse((project / "versions/index.json").exists())
            checked = run(root, TOOL, "example", "--check")
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("still contains template prompts", checked.stderr)

    def test_batch_reads_release_and_detects_drift_and_invalid_yaml(self):
        from yaml import safe_dump

        with TemporaryDirectory() as directory:
            root = Path(directory)
            checkout_fixture(root)
            project = root / "projects/example"
            release = project / "versions/v1.0.0"
            release.mkdir(parents=True)
            manifest = project / "manifest.yaml"
            original = safe_dump(MANIFEST, allow_unicode=True)
            manifest.write_text(original, encoding="utf-8")
            (release.parent / "index.json").write_text('{"current":"1.0.0"}', encoding="utf-8")
            (release / "manifest.json").write_text('{"build":"make build","verify":"make verify"}',
                                                   encoding="utf-8")
            legacy = root / "projects/legacy"
            legacy.mkdir()
            (legacy / "manifest.json").write_text(json.dumps(MANIFEST, ensure_ascii=False), encoding="utf-8")

            generated = run(root, TOOL, "--all", "--write")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertTrue((legacy / "README.zh-CN.md").is_file())
            self.assertEqual(manifest.read_text(encoding="utf-8"), original)
            english = project / "README.md"
            first = english.read_text(encoding="utf-8")
            self.assertIn("# Example v1.0.0", first)
            self.assertIn("```text\nexample\n```", first)
            self.assertIn("make build\nmake verify", first)
            checked = run(root, TOOL, "--all", "--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

            (release / "manifest.json").write_text(
                json.dumps(dict(build="make build", verify="make verify", witness_layout="affine-inline")),
                encoding="utf-8",
            )
            generated = run(root, TOOL, "example", "--write")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertIn("# Example v1.0.0-affine-inline", english.read_text(encoding="utf-8"))
            self.assertIn("# 示例 v1.0.0-affine-inline", (project / "README.zh-CN.md").read_text(encoding="utf-8"))

            updated = dict(MANIFEST, summary={"en": "Updated overview.", "zh-CN": "更新的介绍。"})
            manifest.write_text(safe_dump(updated, allow_unicode=True), encoding="utf-8")
            stale = run(root, TOOL, "--all", "--check")
            self.assertNotEqual(stale.returncode, 0)
            for name in ("README.md", "README.zh-CN.md"):
                self.assertIn(f"projects/example/{name} differs", stale.stderr)
            self.assertEqual(run(root, TOOL, "--all", "--write").returncode, 0)
            self.assertEqual(run(root, TOOL, "--all", "--check").returncode, 0)
            first = english.read_text(encoding="utf-8")
            self.assertIn("Updated overview.", first)

            english.write_text(first + "\nDrift.\n", encoding="utf-8")
            self.assertIn("differs from its manifest", run(root, TOOL, "--all", "--check").stderr)
            manifest.write_text("schema_version: 1\n", encoding="utf-8")
            invalid = run(root, TOOL, "example", "--write")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("required property", invalid.stderr)
            self.assertEqual(english.read_text(encoding="utf-8"), first + "\nDrift.\n")

    def test_checked_in_readmes_match_manifest_outputs(self):
        for project in project_directories(ROOT):
            with self.subTest(project=project.name):
                checked = run(ROOT, TOOL, project.name, "--check")
                self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
