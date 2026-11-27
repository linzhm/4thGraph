"""Scaffold or check the bilingual README for a 4thGraph project."""

import argparse
import json
from pathlib import Path
import re
from string import Template


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "tools" / "templates" / "project-readme"
PROJECT_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PROMPT = "<!-- project-readme:"
LANGUAGES = {
    "README.md": ("en", "Versions", "Protocol", "Wallet SDK quickstart", "Measurements data"),
    "README.zh-CN.md": ("zh-CN", "版本", "协议", "钱包 SDK 快速上手", "实测数据"),
}


def current_version(project):
    index = project / "versions" / "index.json"
    if not index.is_file():
        return None, {}
    catalog = json.loads(index.read_text(encoding="utf-8"))
    version = catalog.get("current") if isinstance(catalog, dict) else None
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError(f"{index.relative_to(ROOT)} needs a current version in X.Y.Z format")
    directory = Path("versions") / f"v{version}"
    manifest = project / directory / "manifest.json"
    return directory, json.loads(manifest.read_text(encoding="utf-8")) if manifest.is_file() else {}


def render(project, filename, title, version_dir, commands):
    language, versions_label, spec_label, sdk_label, data_label = LANGUAGES[filename]
    version_link = f" · [{versions_label}](versions/index.json)" if version_dir else ""
    links = []
    for candidate in (f"docs/spec.{language}.md", f"docs/developer.{language}.md"):
        if (project / candidate).is_file():
            links.append(f"[{spec_label}]({candidate})")
            break
    sdk = project / "docs" / f"sdk.{language}.md"
    if sdk.is_file():
        target = sdk.relative_to(project).as_posix()
        if re.search(r'<a (?:name|id)="quickstart">', sdk.read_text(encoding="utf-8")):
            target += "#quickstart"
        links.append(f"[{sdk_label}]({target})")
    if version_dir and (project / version_dir / "measurements.json").is_file():
        links.append(f"[{data_label}]({(version_dir / 'measurements.json').as_posix()})")
    template = Template((TEMPLATES / f"{filename}.in").read_text(encoding="utf-8"))
    return template.substitute(
        title=title,
        version_link=version_link,
        developer_links="".join(f" · {link}" for link in links),
        commands=commands,
    )


def scaffold(project, titles):
    version_dir, manifest = current_version(project)
    if not isinstance(manifest, dict):
        raise ValueError("version manifest must be a JSON object")
    commands = [manifest[key] for key in ("build", "verify") if manifest.get(key)]
    if any(not isinstance(command, str) for command in commands):
        raise ValueError("version manifest build and verify commands must be text")
    command_block = ""
    if commands:
        command_block = "\n```sh\n" + "\n".join(commands) + "\n```\n"
    rendered = {
        filename: render(project, filename, title, version_dir, command_block)
        for filename, title in titles.items()
    }
    project.mkdir(exist_ok=True)
    for filename, content in rendered.items():
        path = project / filename
        try:
            with path.open("x", encoding="utf-8", newline="\n") as readme:
                readme.write(content)
        except FileExistsError:
            print(f"Kept {path.relative_to(ROOT)}")
        else:
            print(f"Created {path.relative_to(ROOT)}")


def check(project):
    errors = []
    for filename in LANGUAGES:
        path = project / filename
        relative = path.relative_to(ROOT)
        if not path.is_file():
            errors.append(f"{relative} is missing")
            continue
        contents = path.read_text(encoding="utf-8")
        if PROMPT in contents:
            errors.append(f"{relative} still contains template prompts")
    if errors:
        raise ValueError("\n".join(errors))
    print(f"Checked {project.relative_to(ROOT)} README pair")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="project directory name under projects/")
    parser.add_argument("--title", help="English title (defaults to the project name)")
    parser.add_argument("--title-zh", help="Chinese title (defaults to the English title)")
    parser.add_argument("--check", action="store_true", help="check for missing READMEs or unfilled prompts")
    args = parser.parse_args()
    if not PROJECT_SLUG.fullmatch(args.project):
        parser.error("use a lowercase project directory name, for example my-project")
    project = ROOT / "projects" / args.project
    if project.is_symlink():
        parser.error("the project directory must be under projects/")
    title = args.title or args.project
    titles = {"README.md": title, "README.zh-CN.md": args.title_zh or title}
    if any(not name.strip() or len(name.splitlines()) != 1 for name in titles.values()):
        parser.error("README titles must each be one nonempty line")
    try:
        if args.check:
            check(project)
        else:
            scaffold(project, titles)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
