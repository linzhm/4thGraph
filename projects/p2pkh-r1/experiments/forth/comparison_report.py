"""Shared format for R1 comparison and replay reports."""

from hashlib import sha256
import json


SCHEMA_VERSION = 2
PAYMENT_SHAPE = {"inputs": 2, "outputs": 2}


def measured_costs(lock_bytes, otda_program_bytes, payments):
    return {
        "lock_bytes": lock_bytes,
        "otda_program_bytes": otda_program_bytes,
        "payment_bytes": {mode: row["spend"]["bytes"] for mode, row in payments.items()},
        "payment_peak_stack_payload_bytes": {
            mode: row["spend"]["stack"]["combined_payload_bytes"] for mode, row in payments.items()
        },
        "unlock_bytes": {mode: row["unlock_bytes"] for mode, row in payments.items()},
    }


def read_report(path):
    try:
        raw = path.read_bytes()
        report = json.loads(raw)
        if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"expected an R1 comparison report with schema_version {SCHEMA_VERSION}")
        candidates = report.get("candidates")
        if not isinstance(candidates, dict):
            raise ValueError("expected candidates to be an object keyed by name")
        for name, row in candidates.items():
            if not isinstance(row, dict) or not isinstance(row.get("status"), str):
                raise ValueError(f"candidate {name!r} must be an object with a status string")
            for field in ("measured", "estimated"):
                if field in row and not isinstance(row[field], dict):
                    raise ValueError(f"candidate {name!r} must put {field} costs in an object")
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: {error}") from error
    return report, sha256(raw).hexdigest()
