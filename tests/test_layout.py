"""Guard project migration, canonical R1 bytes, and local documentation links."""
import hashlib
import json
import os
from pathlib import Path
import re
from shutil import which
import subprocess
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
                self.assertTrue((project / "manifest.yaml").is_file())
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

    def test_standard_project_docs_link_the_language_pair(self):
        for project in project_directories(ROOT):
            for kind in ("spec", "sdk", "verification"):
                docs = project / "docs"
                english, chinese = (docs / f"{kind}.{locale}.md" for locale in ("en", "zh-CN"))
                if not english.exists() and not chinese.exists():
                    continue
                for page, counterpart in ((english, chinese), (chinese, english)):
                    with self.subTest(page=page.relative_to(ROOT)):
                        self.assertTrue(page.is_file())
                        self.assertRegex(page.read_text(encoding="utf-8"),
                                         r"\]\((?:\./)?" + re.escape(counterpart.name) + r"(?:#[^)]*)?\)")

    def check_local_links(self, root):
        for path in markdown_files(root):
            contents = path.read_text(encoding='utf-8')
            self.assertNotIn('<!-- docs-template:', contents, str(path.relative_to(root)))
            for target in re.findall(r'\]\(([^)]+)\)', contents):
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
            tracked.write_text("<!-- docs-template: unfinished -->\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "docs-template"):
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
