"""Joint layout and evidence planning for typed workflows."""

from graphlib import CycleError, TopologicalSorter
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

from fourthgraph.compiler.lowering import OPTIMIZATIONS
from fourthgraph.compiler.source import CompileError, WORKFLOW_CHOICES, workflow_blockers
from fourthgraph.verification.lineage import lineage_statement
from fourthgraph.verification.stage_proof import GROTH16, TRANSPARENT, StageProof
from fourthgraph.workflow.cpn import canonical, from_build
from fourthgraph.workflow.protocol import (
    OBJECTIVES, artifact_digest, build_artifact, candidate_rank, candidate_sighash_families, normalize_sighash_family,
    normalize_target,
)
from fourthgraph.workflow.workflow_contract import WorkflowContracts, sighash_blocker, state_fields

STAGE_BACKENDS = ("script", TRANSPARENT, GROTH16)
PINNED_CANDIDATE_FIELDS = ("artifact_sha256", "plan_sha256", "stage_roles")


def planned_build(build, *, original=None, selected=None):
    """Check a compiled artifact against its candidate and an optional original report."""
    if build["artifact_sha256"] != artifact_digest(build):
        raise ValueError("invalid build digest")
    plan = from_build(build)
    if plan.digest != build["plan_sha256"]:
        raise ValueError("invalid plan digest")
    report = build["schedule_explanation"]
    identity = report["selected"]
    if selected is not None and selected != identity:
        raise ValueError(f"receipt is for {identity!r}, expected {selected!r}")
    candidate = report["candidates"][identity]
    base_digest = artifact_digest({key: value for key, value in build.items() if key != "schedule_explanation"})
    if (not candidate["eligible"] or candidate["artifact_sha256"] != base_digest
            or candidate["plan_sha256"] != plan.digest):
        raise ValueError("the build does not match its selected candidate")
    if original is not None:
        original = original.get("schedule_explanation", original)
        reference = original["candidates"].get(identity)
        if (not reference or not reference["eligible"]
                or any(report[key] != original[key] for key in ("source_sha256", "imports", "request"))
                or any(candidate.get(key) != reference.get(key) for key in PINNED_CANDIDATE_FIELDS)):
            raise ValueError("receipt does not match the original candidate report")
    return identity, plan


def catalog_from_file(file):
    if file is None:
        return {}, {}, {}
    document = json.loads(file.read_text())
    if not isinstance(document, dict) or not set(document) <= {GROTH16, "evidence_paths", "workflow_paths"}:
        raise ValueError("unknown backend catalog fields")
    proof_setups = document.get(GROTH16, {})
    compositions = document.get("evidence_paths", {})
    workflows = document.get("workflow_paths", {})
    if not all(isinstance(value, dict) for value in (proof_setups, compositions, workflows)):
        raise ValueError("backend catalog entries must be objects")
    if any(not name or set(name) & set("/@~") for name in (*compositions, *workflows)):
        raise ValueError("evidence and workflow path names cannot be empty or contain /, @ or ~")
    setups = {}
    for name, paths in proof_setups.items():
        if (not isinstance(paths, dict) or set(paths) != {"zkey", "ptau"}
                or not all(isinstance(value, str) and value for value in paths.values())):
            raise ValueError(f"{name}: expected zkey and ptau paths")
        setups[name] = tuple((file.parent / paths[key]).resolve() for key in ("zkey", "ptau"))
    return setups, compositions, workflows


def evidence_path(name, document, stages):
    """Check composition before a backend can register a complete lowering.

    Nodes name an output statement and its required predecessor statements.
    The terminal node must establish the stage obligation. Different paths
    may reuse the same node identities with independently selected backends.
    """
    if not isinstance(document, dict) or set(document) != {"stage", "terminal", "nodes"}:
        raise ValueError(f"{name}: expected stage, terminal and nodes")
    stage, terminal, nodes = (document[key] for key in ("stage", "terminal", "nodes"))
    if (not isinstance(stage, str) or stage not in stages or not isinstance(terminal, str)
            or not isinstance(nodes, dict) or not isinstance(nodes.get(terminal), dict)):
        raise ValueError(f"{name}: unknown stage or terminal evidence node")
    dependencies = {}
    for node, spec in nodes.items():
        required = {"backend", "proves", "requires"}
        if not isinstance(spec, dict) or not required <= spec.keys() <= required | {"role"}:
            raise ValueError(f"{name}/{node}: expected backend, proves and requires")
        if (not isinstance(spec["backend"], str) or not spec["backend"]
                or not isinstance(spec["proves"], str) or not spec["proves"]
                or ("role" in spec and (not isinstance(spec["role"], str) or not spec["role"].strip()))
                or not isinstance(spec["requires"], dict)):
            raise ValueError(f"{name}/{node}: invalid evidence descriptor")
        predecessors = spec["requires"]
        if any(not isinstance(nodes.get(dep), dict) or nodes[dep].get("proves") != statement
               for dep, statement in predecessors.items()):
            raise ValueError(f"{name}/{node}: evidence statement mismatch")
        dependencies[node] = tuple(sorted(predecessors))
    if nodes[terminal]["proves"] != stage:
        raise ValueError(f"{name}: terminal evidence does not prove the selected stage")
    try:
        TopologicalSorter(dependencies).prepare()
    except CycleError as error:
        raise ValueError(f"{name}: cycle in evidence dependencies") from error
    needed = {terminal}
    pending = [terminal]
    while pending:
        for node in dependencies[pending.pop()]:
            if node not in needed:
                needed.add(node)
                pending.append(node)
    if needed != nodes.keys():
        raise ValueError(f"{name}: evidence nodes do not feed the terminal verifier")
    graph = TopologicalSorter(dependencies)
    graph.prepare()
    ordered = []
    while graph.is_active():
        group = sorted(graph.get_ready())
        ordered.extend(group)
        graph.done(*group)
    return {"stage": stage, "terminal": terminal,
            "nodes": [{"id": node, **nodes[node]} for node in ordered]}


def workflow_path(name, document, workflow):
    if not isinstance(document, dict) or set(document) != {"layout", "stages"}:
        raise ValueError(f"{name}: expected a layout and stage roles")
    layout, roles = document["layout"], document["stages"]
    if (layout not in WORKFLOW_CHOICES or not isinstance(roles, dict)
            or set(roles) != {stage.name for stage in workflow.stages}):
        raise ValueError(f"{name}: invalid layout or incomplete stage roles")
    allocated = []
    for stage in workflow.stages:
        spec = roles[stage.name]
        if (not isinstance(spec, dict) or set(spec) != {"role", "backend"}
                or not isinstance(spec["backend"], str) or not spec["backend"].strip()
                or not isinstance(spec["role"], str) or not spec["role"].strip()):
            raise ValueError(f"{name}/{stage.name}: expected a role and backend")
        allocated.append({"stage": stage.name, **spec})
    first, last = allocated[0]["backend"], allocated[-1]["backend"]
    pair = last if first == "script" else f"{first}+{last}"
    supported = (first in STAGE_BACKENDS and last in STAGE_BACKENDS
                 and all(spec["backend"] == "script" for spec in allocated[1:-1]))
    return f"{layout}/{pair}" if supported else None, allocated


def compile_evidence_plans(frontend, keys, current, directory, *, mode, target, optimization, objective,
                           available_authorizers, sighash_family, catalog=None, max_tx_bytes=None,
                           max_lock_bytes=None, max_constraints=None, optimizations=None, selected=None):
    if mode not in ("auto", *WORKFLOW_CHOICES):
        raise CompileError("unknown workflow layout")
    profiles = tuple(optimizations) if optimizations is not None else (optimization,)
    if not profiles or len(set(profiles)) != len(profiles) or set(profiles) - set(OPTIMIZATIONS):
        raise CompileError("expected distinct compiler optimizations")
    target, sighash_family = normalize_target(target), normalize_sighash_family(sighash_family)
    families = candidate_sighash_families(target, sighash_family)
    workflow = frontend.workflow()
    stages = {stage.name: stage for stage in workflow.stages}
    recursive = [lineage_statement(frontend, name) for name in frontend.recursions]
    configs, paths, workflows = catalog_from_file(catalog)
    if configs.keys() - stages.keys():
        raise CompileError("backend catalog names an unknown stage")
    last = workflow.stages[-1]
    available = {stage.owner for stage in workflow.stages} if available_authorizers is None else set(available_authorizers)
    candidates, contracts, artifacts = {}, {}, {}
    compiled = {}

    def exclude(code, message, stage=None):
        result = {"code": code, "message": message}
        if stage is not None:
            result.update(stage=stage.name, line=stage.declaration.line)
        return result

    def suffix(family, profile):
        sighash = f"@{family}" if sighash_family == "auto" and family != "bip143" else ""
        lowering = f"~{profile}" if optimizations is not None else ""
        return sighash + lowering

    def build(layout, first_backend, backend, family, profile):
        selected_methods = {workflow.stages[0].name: first_backend, last.name: backend}
        reasons = workflow_blockers(workflow, layout, available)
        pending = []
        for stage in workflow.stages:
            method = selected_methods.get(stage.name, "script")
            if method != "script":
                pending.append((stage, method))
                if method == TRANSPARENT and (stage.private or stage.policy == "require-zk"):
                    reasons.append(exclude("private_witness_disclosure", "the full assignment would be exposed", stage))
                elif method == TRANSPARENT and not stage.assignment_disclosure:
                    reasons.append(exclude("assignment_disclosure_required", "the full assignment needs approval", stage))
                if method == GROTH16 and stage.name not in configs:
                    reasons.append(exclude("missing_setup", "no matching stage setup was supplied", stage))
                continue
            if stage.private:
                reasons.append(exclude("private_witness_disclosure", "Script would disclose a private operand", stage))
            elif stage.policy != "allow-direct":
                reasons.append(exclude("proof_required", "the stage requires a proof", stage))
            elif stage.witnesses:
                reasons.append(exclude("unsupported_witness_layout", "Script witness operands are unavailable", stage))
        if recursive:
            reasons.append(exclude("recursive_backend_unavailable", "no recursive predicate is linked to the workflow"))
        if any(visibility.name == "private" for _, _, visibility in workflow.places):
            reasons.append(exclude("private_state_unavailable", "this build needs all stage boundaries public"))

        if pending and (family != "bip143" or len(workflow.stages) != 2 or
                        layout == "fused-prefix" or workflow.recovery):
            reasons.append(exclude("unsupported_proof_layout", "the proof linker needs two BIP143 stages", last))
        if first_backend != "script" and workflow.stages[0].witnesses:
            reasons.append(exclude("unsupported_witness_layout", "the first proof stage needs a public state operand"))
        blocker = sighash_blocker(workflow, layout, family)
        if blocker:
            reasons.append(blocker)
        if reasons:
            return None, None, reasons

        proofs = {}
        for stage, method in pending:
            key = stage.name, method
            if key not in compiled:
                try:
                    compiled[key] = StageProof(stage, Path(directory) / stage.name / method,
                                               method, configs.get(stage.name))
                except (OSError, ValueError) as error:
                    compiled[key] = exclude("backend_build_failed", str(error), stage)
            result = compiled[key]
            if isinstance(result, dict):
                reasons.append(result)
            else:
                proofs[stage.name] = result
                if max_constraints is not None and result.constraints > max_constraints:
                    reasons.append(exclude("constraint_budget", "stage circuit exceeds the constraint budget", stage))
        if reasons:
            return None, None, reasons

        try:
            contract = WorkflowContracts(workflow, keys, current, mode=layout, target=target,
                                         optimization=profile, available_authorizers=available,
                                         objective=objective, max_tx_bytes=max_tx_bytes, sighash_family=family,
                                         proof=proofs.get(last.name), first_proof=proofs.get(workflow.stages[0].name))
            artifact = contract.artifact(frontend.source.encode())
        except ValueError as error:
            return None, None, [exclude("layout_build_failed", str(error))]
        return contract, artifact, reasons

    layouts = WORKFLOW_CHOICES if mode == "auto" else (mode,)
    for layout in layouts:
        first_methods = STAGE_BACKENDS if layout == "atomic" else ("script",)
        for first_backend, backend, family, profile in product(first_methods, STAGE_BACKENDS, families, profiles):
            pair = backend if first_backend == "script" else f"{first_backend}+{backend}"
            identity = f"{layout}/{pair}{suffix(family, profile)}"
            contract, artifact, reasons = build(layout, first_backend, backend, family, profile)
            row = {"layout": layout, "backend": backend, "first_backend": first_backend,
                   "sighash_family": family, "optimization": profile, "measurement": "not_built"}
            if artifact:
                cost = artifact["estimated_cost"]
                lock_sizes = [len(item.script) for item in contract.deployment_outputs]
                lock_sizes.extend(len(state_fields(bytes(32), 0) + code)
                                  for _, code in getattr(contract, "state_codes", {}).values())
                largest_lock = max(lock_sizes)
                for code, estimated, limit in (
                    ("transaction_byte_budget", cost["max_transaction_bytes"], max_tx_bytes),
                    ("lock_byte_budget", largest_lock, max_lock_bytes),
                ):
                    if limit is not None and estimated > limit:
                        reasons.append({**exclude(code, f"{estimated} B exceeds the {limit} B budget"),
                                        "limit": limit, "estimated": estimated})
                row.update(measurement="estimate", artifact_sha256=artifact["artifact_sha256"], plan_sha256=artifact["plan_sha256"],
                           graph=artifact["transaction_graph"], cost=cost, max_lock_bytes=largest_lock,
                           rank=candidate_rank(cost, OBJECTIVES[objective]))
                if "stage_evidence" in artifact:
                    row["stage_evidence"] = artifact["stage_evidence"]
                template = {stage: step for step in artifact["templates"] for stage in step["executes"]}
                row["assertions"] = [{
                    "stage": stage.name, "word": stage.word.name, "line": stage.declaration.line,
                    "transaction": template[stage.name]["name"],
                    "vin": 1 if layout == "atomic" and stage is last else 0,
                    "backend": backend if stage is last else first_backend if stage is workflow.stages[0] else "script",
                    "state": stage.source.name, "authorizer": stage.owner, "policy": stage.policy,
                    "binding": "actual prevout and ordered successor outputs",
                } for stage in workflow.stages]
            row.update(eligible=not reasons, exclusions=reasons)
            candidates[identity] = row
            if not reasons:
                contracts[identity], artifacts[identity] = contract, artifact

    for name, document in sorted(workflows.items()):
        base, roles = workflow_path(name, document, workflow)
        for family, profile in product(families, profiles):
            variant = suffix(family, profile)
            identity = f"path/{name}{variant}"
            canonical_candidate = f"{base}{variant}" if base is not None else None
            row = candidates.get(canonical_candidate, {"eligible": False, "measurement": "not_built", "exclusions": [
                exclude("workflow_path_unavailable", "no linker supports this stage allocation in the requested layouts")
            ]})
            candidates[identity] = {**row, "canonical_candidate": canonical_candidate, "stage_roles": roles}
            if canonical_candidate in contracts:
                contracts[identity], artifacts[identity] = contracts[canonical_candidate], artifacts[canonical_candidate]

    for name, document in sorted(paths.items()):
        candidates[f"evidence/{name}"] = {
            "eligible": False, "measurement": "not_built", "evidence_graph": evidence_path(name, document, stages),
            "exclusions": [exclude("composed_verifier_unavailable",
                                   "no registered lowering verifies this evidence composition")],
        }

    eligible = sorted(contracts, key=lambda name: (candidates[name]["rank"], name.startswith("path/"), name))
    choice = selected if selected is not None else (eligible[0] if eligible else None)
    if choice is not None and choice not in contracts:
        raise CompileError(f"candidate {choice!r} is unavailable")
    request = dict(mode=mode, target=target, optimization=optimization, objective=objective,
                   current=current, available_authorizers=sorted(available), sighash_family=sighash_family,
                   max_tx_bytes=max_tx_bytes, max_lock_bytes=max_lock_bytes, max_constraints=max_constraints,
                   keys={key: value.hex() for key, value in keys.items()})
    if optimizations is not None:
        request["optimizations"] = profiles
    report = {
        "schema_version": 1, "request": request, "source_sha256": sha256(frontend.source.encode()).hexdigest(),
        "imports": frontend.source_imports, "objective": objective, "selected": choice,
        "rank_order": OBJECTIVES[objective], "ranked_candidates": eligible,
        "candidates": candidates, "recursive_statements": recursive,
    }
    if choice is None:
        return None, report
    return contracts[choice], build_artifact({**artifacts[choice], "schedule_explanation": report},
                                              frontend.source.encode())


def rebuild_candidate(frontend, report, name, directory, catalog):
    report = report.get("schedule_explanation", report)
    if report["source_sha256"] != sha256(frontend.source.encode()).hexdigest():
        raise CompileError("candidate source digest changed")
    if report["imports"] != frontend.source_imports:
        raise CompileError("candidate import digests changed")
    entry = report["candidates"].get(name)
    if entry is None or not entry["eligible"]:
        raise CompileError(f"candidate {name!r} is unavailable")
    request = dict(report["request"])
    keys = {role: bytes.fromhex(key) for role, key in request.pop("keys").items()}
    current = request.pop("current")
    contract, artifact = compile_evidence_plans(frontend, keys, current, directory,
                                                catalog=catalog, selected=name, **request)
    rebuilt = artifact["schedule_explanation"]["candidates"][name]
    if any(rebuilt.get(key) != entry.get(key) for key in PINNED_CANDIDATE_FIELDS):
        raise CompileError("candidate artifacts changed")
    return contract, artifact
