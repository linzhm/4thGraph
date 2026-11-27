"""Lower an executable CPN and explore transaction/proof candidates in one command."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.workflow.logical_cpn_lowering import lower_linear


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
        _, generated = lower_linear(json.loads(raw), source.read_text(encoding="utf8"), source_path=source)
        # The compiler source digest commits to the exact model input. This is
        # provenance, not a substitute for re-running lowering or verifying Script.
        generated += "\\ logical-cpn-sha256 " + sha256(raw).hexdigest() + "\n"
        with output.open("x", encoding="utf8", newline="\n") as stream:
            stream.write(generated)
    except (OSError, TypeError, ValueError) as error:
        cli.error(str(error))

    from fourthgraph.workflow.protocol import main as compiler_main

    return compiler_main([str(output), *options], cpn_action="tune")
