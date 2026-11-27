"""Lower an executable CPN and explore transaction/proof candidates in one command."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.workflow.logical_cpn_lowering import lower_linear


def render_model(raw_model, source, *, source_path):
    """Generate the exact workflow used by tune-model, with model provenance."""
    frontend, generated = lower_linear(json.loads(raw_model), source, source_path=source_path)
    generated += "\\ logical-cpn-sha256 " + sha256(raw_model).hexdigest() + "\n"
    return frontend, generated


def verify_model(model, source, workflow, report=None):
    """Re-lower a model and compare the workflow and optional report provenance.

    This does not rerun candidate search, verify a proof, or inspect chain state.
    """
    model, source, workflow = model.resolve(), source.resolve(), workflow.resolve()
    if workflow.parent != source.parent or workflow in (source, model):
        raise ValueError("workflow must be a separate file in the Forth source directory")
    raw_model = model.read_bytes()
    frontend, expected = render_model(raw_model, source.read_text(encoding="utf8"), source_path=source)
    workflow_bytes = workflow.read_bytes()
    if workflow_bytes != expected.encode("utf8"):
        raise ValueError("workflow does not match the model and Forth source")
    workflow_digest = sha256(workflow_bytes).hexdigest()
    result = {"schema_version": 1, "scope": "logical-model-lowering-provenance",
              "model_sha256": sha256(raw_model).hexdigest(), "workflow_sha256": workflow_digest,
              "imports": frontend.source_imports, "report_checked": False,
              "not_checked": ["candidate search", "proof verification", "transaction execution", "chain state"]}
    if report is not None:
        report_bytes = report.read_bytes()
        build = json.loads(report_bytes)
        if not isinstance(build, dict):
            raise ValueError("expected a candidate report object")
        rows = build.get("schedule_explanation", build)
        if not isinstance(rows, dict) or not isinstance(rows.get("candidates"), dict):
            raise ValueError("expected a candidate report")
        if rows.get("source_sha256") != workflow_digest or rows.get("imports") != frontend.source_imports:
            raise ValueError("candidate report differs from the workflow or its imports")
        if "schedule_explanation" in build:
            from fourthgraph.workflow.proof_planner import planned_build

            planned_build(build)
        result.update(report_checked=True, report_sha256=sha256(report_bytes).hexdigest())
    return result


def main(argv):
    cli = argparse.ArgumentParser(prog="4thgraph cpn tune-model", description=__doc__,
                                  epilog="Pass cpn tune options such as --keys and --current after these arguments.")
    cli.add_argument("model", type=Path)
    cli.add_argument("--source", type=Path, required=True, help="Forth words used by the model")
    cli.add_argument("--output", type=Path, required=True, help="new generated workflow beside the source")
    args, options = cli.parse_known_args(argv)
    forbidden = {"--select-candidate", "--entry", "--cpn", "--cpn-plan", "--capabilities", "--version"}
    if any(option.split("=", 1)[0] in forbidden for option in options):
        cli.error("tune-model only accepts candidate exploration options")
    source = args.source.resolve()
    output = args.output.resolve()
    model = args.model.resolve()
    if output.parent != source.parent or output in (source, model):
        cli.error("output must be a separate new file in the Forth source directory")
    try:
        raw = model.read_bytes()
        _, generated = render_model(raw, source.read_text(encoding="utf8"), source_path=source)
        with output.open("x", encoding="utf8", newline="\n") as stream:
            stream.write(generated)
    except (OSError, TypeError, ValueError) as error:
        cli.error(str(error))

    from fourthgraph.workflow.protocol import main as compiler_main

    return compiler_main([str(output), *options], cpn_action="tune")
