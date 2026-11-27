"""Validate project manifests and regenerate or check README pairs with Copier."""

import argparse
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory

try:
    from copier import run_copy
    from copier.errors import CopierError
    from jsonschema import Draft202012Validator
    from yaml import YAMLError, safe_load
except ModuleNotFoundError as error:
    raise SystemExit("Install the documentation tools with python3 -m pip install -r tools/requirements-docs.txt") from error


ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ROOT / "projects"
TEMPLATE = PROJECTS / "template"
MANIFEST_NAMES = ("manifest.yaml", "manifest.json")
READMES = {"en": "README.md", "zh-CN": "README.zh-CN.md"}
PROMPT = "<!-- project-readme:"


def load(path):
    try:
        source = path.read_text(encoding="utf-8")
        data = safe_load(source) if path.suffix == ".yaml" else json.loads(source)
    except (ValueError, YAMLError) as error:
        raise ValueError(f"{path.relative_to(ROOT)}: {error}") from error
    if not isinstance(data, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain an object")
    return data


def readme_context(project, manifest):
    data = {"manifest": manifest.name}
    index = project / "versions" / "index.json"
    if index.is_file():
        version = load(index).get("current")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError(f"{index.relative_to(ROOT)} needs a current version in X.Y.Z format")
        release = Path("versions") / f"v{version}"
        metadata = load(project / release / "manifest.json")
        commands = [metadata.get(key) for key in ("build", "verify")]
        if any(not isinstance(command, str) or not command.strip() for command in commands):
            raise ValueError(f"{project.name}/{release}/manifest.json needs build and verify commands")
        layout = metadata.get("witness_layout")
        if layout is not None and (not isinstance(layout, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", layout)):
            raise ValueError(f"{project.name}/{release}/manifest.json needs a lowercase witness layout name")
        data.update(version=version, version_label=f"{version}-{layout}" if layout else version, commands=commands)
        measurements = release / "measurements.json"
        if (project / measurements).is_file():
            data["measurements"] = measurements.as_posix()

    for locale, filename in READMES.items():
        links = {}
        for protocol in (f"docs/spec.{locale}.md", f"docs/developer.{locale}.md"):
            if (project / protocol).is_file():
                links["protocol"] = protocol
                break
        sdk = f"docs/sdk.{locale}.md"
        if (project / sdk).is_file():
            contents = (project / sdk).read_text(encoding="utf-8")
            links["sdk"] = sdk + ("#quickstart" if re.search(r'<a (?:name|id)="quickstart">', contents) else "")
            if (ROOT / "sdk" / filename).is_file():
                links["unified_sdk"] = f"../../sdk/{filename}#quickstart"
        data[locale] = links
    return data


def process_project(project, validator, *, write):
    if project.is_symlink():
        raise ValueError(f"{project.relative_to(ROOT)} must be a project directory")
    manifests = [project / name for name in MANIFEST_NAMES if (project / name).is_file()]
    if len(manifests) != 1:
        raise ValueError(f"{project.relative_to(ROOT)} needs one project manifest. Use manifest.yaml.")
    manifest = manifests[0]
    data = load(manifest)
    errors = sorted(validator.iter_errors(data), key=lambda error: error.json_path)
    if errors:
        raise ValueError("\n".join(
            f"{manifest.relative_to(ROOT)} {error.json_path}: {error.message}" for error in errors
        ))
    context = dict(data, scaffold=False, readme=readme_context(project, manifest))
    with TemporaryDirectory(dir=project) as directory:
        staging = Path(directory)
        run_copy(str(TEMPLATE), staging, data=context, defaults=True, quiet=True)
        changed = []
        errors = []
        for filename in READMES.values():
            rendered = (staging / filename).read_bytes()
            readme = project / filename
            label = readme.relative_to(ROOT)
            if readme.is_symlink() or (readme.exists() and not readme.is_file()):
                raise ValueError(f"{label} must be a regular file")
            if not readme.exists() or readme.read_bytes() != rendered:
                changed.append(filename)
                if not write:
                    errors.append(f"{label} differs from its manifest. Run with --write.")
            if not write and PROMPT.encode() in rendered:
                errors.append(f"{label} still contains template prompts")
        if errors:
            raise ValueError("\n".join(errors))
        for filename in changed:
            (staging / filename).replace(project / filename)
            print(f"Wrote {(project / filename).relative_to(ROOT)}")
    if not write:
        print(f"Checked {project.relative_to(ROOT)} README pair")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("project", nargs="?", help="project directory name under projects/")
    target.add_argument("--all", action="store_true", help="process all projects with a project manifest")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="regenerate both READMEs with Copier")
    action.add_argument("--check", action="store_true", help="report unfinished prompts or README drift")
    args = parser.parse_args()

    if args.all:
        projects = sorted(project for project in PROJECTS.iterdir()
                          if project != TEMPLATE and any((project / name).is_file() for name in MANIFEST_NAMES))
    else:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.project) or args.project == TEMPLATE.name:
            parser.error("use a project directory name under projects/, for example my-project")
        projects = [PROJECTS / args.project]
    validator = Draft202012Validator(load(TEMPLATE / "manifest.schema.json"))
    errors = []
    for project in projects:
        try:
            process_project(project, validator, write=args.write)
        except (OSError, ValueError, CopierError) as error:
            errors.append(str(error))
    if errors:
        parser.exit(1, "\n".join(errors) + "\n")


if __name__ == "__main__":
    main()
