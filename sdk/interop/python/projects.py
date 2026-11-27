"""Replay the wallet templates selected by the project release indexes."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from bsv.transaction import Transaction as BsvTransaction

from fourthgraph.bsv.transaction import Transaction
from sdk.python.bridge import ROOT, WALLET_PROJECTS


def profiles(project, version, manifest):
    if project == "p2pk-p2pkh-baseline":
        return ("p2pk", "p2pkh")
    if project == "ml-dsa":
        return ("pure-ml-dsa-44",)
    if project == "lamport-ots":
        if version == "0.1.0":
            return ("committed-key-forth-compact",)
        return (f"committed-key-forth-v{version}",)
    return (manifest.get("template", f"v{version}"),)


def verify_transactions(rows, project, release):
    for row in rows:
        funding = BsvTransaction.from_hex(row["funding"])
        signed = BsvTransaction.from_hex(row["signed"])
        txid = Transaction.parse(bytes.fromhex(row["signed"])).txid()
        if (funding is None or signed is None or funding.hex() != row["funding"]
                or signed.hex() != row["signed"] or signed.txid() != txid):
            raise ValueError(f"{project} v{release}: Python SDK changed transaction framing")
        (tx_input,) = signed.inputs
        vout = row["vout"]
        if tx_input.source_txid != funding.txid() or tx_input.source_output_index != vout:
            raise ValueError(f"{project} v{release}: Python SDK returned a different outpoint")
        yield {
            "project": project,
            "release": release,
            "funding": row["funding"],
            "signed": row["signed"],
            "txid": txid,
            "vout": vout,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("projects", nargs="*", metavar="PROJECT")
    args = parser.parse_args()
    projects = list(dict.fromkeys(args.projects)) or sorted(WALLET_PROJECTS)
    unknown = set(projects) - WALLET_PROJECTS
    if unknown:
        parser.error(f"unknown wallet projects: {', '.join(sorted(unknown))}")

    cases = []
    for project in projects:
        versions = ROOT / "projects" / project / "versions"
        index = json.loads((versions / "index.json").read_text(encoding="utf-8"))
        releases = dict.fromkeys(index[key] for key in ("current", "next") if key in index)
        for release in releases:
            manifest = json.loads((versions / f"v{release}" / "manifest.json").read_text(encoding="utf-8"))
            vector_path = args.file.parent / f"{project}-v{release}.json"
            command = [sys.executable, str(ROOT / "sdk/tests/wallet_vectors.py"), project, str(vector_path)]
            for profile in profiles(project, release, manifest):
                command.extend(("--profile", profile))
            subprocess.run(command, check=True)
            rows = json.loads(vector_path.read_text(encoding="utf-8"))
            cases.extend(verify_transactions(rows, project, release))
            print(f"Python SDK: {project} v{release}, {len(rows)} transactions", flush=True)
    args.file.write_text(json.dumps(cases), encoding="utf-8")


if __name__ == "__main__":
    main()
