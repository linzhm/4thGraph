"""Scaffold and regenerate bilingual 4thGraph project READMEs."""

import argparse
import json
from pathlib import Path
import re
from string import Template
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "projects" / "template"
PROJECT_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
LINE = re.compile(r"[^\r\n]*\S[^\r\n]*")
PROMPT = "<!-- project-readme:"
GENERATED = "<!-- Generated from manifest.json by tools/project_readme.py. -->\n\n"
LANGUAGES = {
    "en": ("README.md", "Versions", "Protocol", "Wallet SDK quickstart", "Unified wallet SDK",
           "Measurements data", "Entry point", "Purpose"),
    "zh-CN": ("README.zh-CN.md", "版本", "协议", "钱包 SDK 快速上手", "统一钱包 SDK",
              "实测数据", "入口", "用途"),
}
SECTIONS = {
    "use_cases": ("Use cases and trade-offs", "使用场景与取舍"),
    "algorithm": ("Algorithm and execution", "算法与执行"),
    "reproduction": ("Reproduce the checks", "复现方法"),
    "script_sizes": ("Script sizes", "脚本尺寸"),
    "integration": ("Developer and wallet integration", "开发和钱包接入"),
    "transactions": ("Complete transactions and stack measurements", "完整交易与栈测量"),
    "lifecycle": ("Marginal and lifecycle costs", "输入输出边际与生命周期"),
}


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path.relative_to(ROOT)}: {error}") from error


def version_context(project):
    index = project / "versions" / "index.json"
    if not index.is_file():
        return None, ""
    catalog = read_json(index)
    version = catalog.get("current") if isinstance(catalog, dict) else None
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError(f"{index.relative_to(ROOT)} needs a current version in X.Y.Z format")
    directory = Path("versions") / f"v{version}"
    path = project / directory / "manifest.json"
    manifest = read_json(path) if path.is_file() else {}
    if not isinstance(manifest, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must be a JSON object")
    commands = [manifest[key] for key in ("build", "verify") if key in manifest]
    if any(not isinstance(command, str) or not command.strip() for command in commands):
        raise ValueError(f"{path.relative_to(ROOT)} build and verify commands must be nonempty text")
    return directory, "```sh\n" + "\n".join(commands) + "\n```" if commands else ""


def check_keys(value, path, required, optional=()):
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing:
        raise ValueError(f"{path} is missing {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{path} has unknown fields: {', '.join(sorted(extra))}")


def validate_localized(value, path, *, blocks=False):
    check_keys(value, path, LANGUAGES)
    for locale, content in value.items():
        if blocks:
            if not isinstance(content, list) or not content or any(
                not isinstance(block, str) or not block.strip() for block in content
            ):
                raise ValueError(f"{path}.{locale} must contain nonempty Markdown blocks")
        elif not isinstance(content, str) or not LINE.fullmatch(content):
            raise ValueError(f"{path}.{locale} must be one nonempty line")


def validate_manifest(data):
    check_keys(data, "manifest.json", ("schema_version", "title", "summary", "entry_points", "sections"),
               ("$schema", "setup"))
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("manifest.json schema_version must be 1")
    if "$schema" in data and (not isinstance(data["$schema"], str) or not data["$schema"]):
        raise ValueError("manifest.json $schema must be a string")
    for field in ("title", "summary"):
        validate_localized(data[field], field)
    if not isinstance(data["entry_points"], list):
        raise ValueError("entry_points must be an array")
    for index, entry in enumerate(data["entry_points"]):
        path = f"entry_points[{index}]"
        check_keys(entry, path, ("name", "description"))
        if not isinstance(entry["name"], str) or not LINE.fullmatch(entry["name"]):
            raise ValueError(f"{path}.name must be one nonempty line")
        validate_localized(entry["description"], f"{path}.description")
    check_keys(data["sections"], "sections", ("algorithm", "reproduction"), SECTIONS)
    for key, content in data["sections"].items():
        validate_localized(content, f"sections.{key}", blocks=True)
    if "setup" in data:
        validate_localized(data["setup"], "setup", blocks=True)


def render(project, data, locale, version_dir, commands, *, generated):
    filename, versions, protocol, sdk, unified_sdk, measurements, entry_label, purpose = LANGUAGES[locale]
    column = 0 if locale == "en" else 1
    sections = data["sections"]
    links = []
    for candidate in (f"docs/spec.{locale}.md", f"docs/developer.{locale}.md"):
        if (project / candidate).is_file():
            links.append(f"[{protocol}]({candidate})")
            break
    for key in ("algorithm", "reproduction", "transactions"):
        if key in sections:
            title = SECTIONS[key][column]
            links.append(f"[{title}](#{title.lower().replace(' ', '-')})")
    quickstart = []
    sdk_guide = f"docs/sdk.{locale}.md"
    if (project / sdk_guide).is_file():
        has_anchor = re.search(r'<a (?:name|id)="quickstart">', (project / sdk_guide).read_text(encoding="utf-8"))
        target = sdk_guide + ("#quickstart" if has_anchor else "")
        quickstart.append(f"**[{sdk}]({target})**")
        if (ROOT / "sdk" / filename).is_file():
            quickstart.append(f"[{unified_sdk}](../../sdk/{filename}#quickstart)")
    if version_dir and (project / version_dir / "measurements.json").is_file():
        links.append(f"[{measurements}]({(version_dir / 'measurements.json').as_posix()})")

    table = [f"| {entry_label} | {purpose} |", "| --- | --- |"]
    for entry in data["entry_points"]:
        name = entry["name"].replace("|", r"\|")
        description = entry["description"][locale].replace("|", r"\|")
        table.append(f"| `{name}` | {description} |")

    body = []
    for key, headings in SECTIONS.items():
        if key not in sections:
            continue
        body.append(f"## {headings[column]}")
        if key == "reproduction":
            body.extend(data.get("setup", {}).get(locale, ()))
            if commands:
                body.append(commands)
        body.extend(sections[key][locale])

    title = data["title"][locale]
    if generated and version_dir:
        title = f"{title} {version_dir.name}"
    template = Template((TEMPLATES / f"{filename}.in").read_text(encoding="utf-8"))
    return template.substitute(
        generated=GENERATED if generated else "",
        title=title,
        version_link=f" · [{versions}](versions/index.json)" if version_dir else "",
        quickstart=" · ".join(quickstart) + "\n\n" if quickstart else "",
        summary=data["summary"][locale],
        navigation=" · ".join(links) + "\n\n",
        entry_points="\n".join(table) + "\n\n" if data["entry_points"] else "",
        sections="\n\n".join(body),
    )


def render_pair(project, data, *, generated):
    validate_manifest(data)
    version_dir, commands = version_context(project)
    return {
        labels[0]: render(project, data, locale, version_dir, commands, generated=generated)
        for locale, labels in LANGUAGES.items()
    }


def write_pair(project, rendered, *, replace):
    project.mkdir(exist_ok=True)
    if replace:
        with TemporaryDirectory(dir=project) as temporary:
            staging = Path(temporary)
            for filename, content in rendered.items():
                path = project / filename
                if path.is_symlink() or (path.exists() and not path.is_file()):
                    raise ValueError(f"{path.relative_to(ROOT)} must be a regular file")
                if path.is_file() and path.read_text(encoding="utf-8") == content:
                    continue
                (staging / filename).write_text(content, encoding="utf-8", newline="\n")
            for staged in staging.iterdir():
                path = project / staged.name
                staged.replace(path)
                print(f"Wrote {path.relative_to(ROOT)}")
        return
    for filename, content in rendered.items():
        path = project / filename
        try:
            with path.open("x", encoding="utf-8", newline="\n") as readme:
                readme.write(content)
        except FileExistsError:
            print(f"Kept {path.relative_to(ROOT)}")
        else:
            print(f"Wrote {path.relative_to(ROOT)}")


def check(project, expected=None):
    errors = []
    for filename, *_ in LANGUAGES.values():
        path = project / filename
        relative = path.relative_to(ROOT)
        if not path.is_file():
            errors.append(f"{relative} is missing")
            continue
        contents = path.read_text(encoding="utf-8")
        if PROMPT in contents:
            errors.append(f"{relative} still contains template prompts")
        if expected is not None and contents != expected[filename]:
            errors.append(f"{relative} differs from its manifest. Run with --write.")
    if errors:
        raise ValueError("\n".join(errors))
    print(f"Checked {project.relative_to(ROOT)} README pair")


def scaffold_project(project, data):
    if project.exists():
        raise FileExistsError(f"{project.relative_to(ROOT)} already exists")
    rendered = render_pair(project, data, generated=True)
    with TemporaryDirectory(dir=project.parent) as temporary:
        staging = Path(temporary) / project.name
        staging.mkdir()
        for name in ("docs", "reference", "versions"):
            (staging / name).mkdir()
        (staging / "manifest.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        for filename, content in rendered.items():
            (staging / filename).write_text(content, encoding="utf-8", newline="\n")
        project.mkdir()
        try:
            staging.replace(project)
        except OSError:
            project.rmdir()
            raise
    print(f"Created {project.relative_to(ROOT)}. Edit manifest.json, then run with --write.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="project directory name under projects/")
    parser.add_argument("--title", help="English draft title (defaults to the project name)")
    parser.add_argument("--title-zh", help="Chinese draft title (defaults to the English title)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scaffold", action="store_true", help="create a new project with docs, source, and version directories")
    mode.add_argument("--init", action="store_true", help="create an editable project manifest")
    mode.add_argument("--write", action="store_true", help="regenerate both READMEs from the project manifest")
    mode.add_argument("--check", action="store_true", help="check the README pair and any manifest drift")
    args = parser.parse_args()
    if not PROJECT_SLUG.fullmatch(args.project):
        parser.error("use a lowercase project directory name, for example my-project")
    project = ROOT / "projects" / args.project
    if project == TEMPLATES:
        parser.error("projects/template is reserved for the shared README templates")
    if project.is_symlink():
        parser.error("the project directory must be under projects/")
    manifest = project / "manifest.json"
    try:
        if args.write and not manifest.is_file():
            raise ValueError(f"{manifest.relative_to(ROOT)} is missing. Run with --init.")
        if args.check and not manifest.is_file():
            check(project)
            return
        if args.init or args.scaffold or not manifest.is_file():
            data = read_json(TEMPLATES / "manifest.example.json")
            title = args.title or args.project
            data["title"] = {"en": title, "zh-CN": args.title_zh or title}
        else:
            data = read_json(manifest)
        if args.init or args.scaffold:
            data["$schema"] = f"../{TEMPLATES.name}/manifest.schema.json"
        if args.scaffold:
            scaffold_project(project, data)
            return
        if args.init:
            validate_manifest(data)
            project.mkdir(exist_ok=True)
            with manifest.open("x", encoding="utf-8", newline="\n") as output:
                json.dump(data, output, ensure_ascii=False, indent=2)
                output.write("\n")
            print(f"Created {manifest.relative_to(ROOT)}")
            return
        rendered = render_pair(project, data, generated=manifest.is_file())
        if args.check:
            check(project, rendered)
        else:
            write_pair(project, rendered, replace=args.write)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
