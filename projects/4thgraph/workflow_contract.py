"""Bind a typed workflow to fused, serial or atomic covenant spends."""

from dataclasses import asdict
from types import MappingProxyType

from compiler import (
    PROJECT_NAME, PROJECT_VERSION, WORKFLOW_MODES, CompileError, ParentOutput, Template,
    evaluate, plan_workflow, workflow_blockers, workflow_layout,
)
from forkid_lowering import COPY_LINKED_SIGHASH, LINKED_OUTPOINT_OFFSET, DualLinkedContext, LinkedContext
from lowering import BASELINE, compile_word
from protocol import (
    BINDING_CODE, CURRENT_OUTPOINT, DEFAULT_TARGET, FLAG, OBJECTIVES, OUTPUTS_HASH, PREVOUTS_HASH, REFUND_SEQUENCE,
    RESULT_WIDTH, ROOT_VALUE, SIGHASH_FAMILIES, SIGHASH_FAMILY_OPTIONS, TARGETS, TERMINAL_VALUE,
    Draft, UTXO, authorize, begin, build_artifact, candidate_rank, check_field, check_version, copy_preimage, estimate_cost,
    field, finish, input_value, is_compressed_public_key, p2pk, recoverable_lock, refund_output,
    single_input, validate_u32,
)
from shared.script import asm, encode_num, number, push
from shared.transaction import Input, Output, Transaction

STATE_VALUE = (ROOT_VALUE + TERMINAL_VALUE) // 2
ZERO_INDEX = bytes(4)
SIBLING_INDEX = (1).to_bytes(4, "little")
RECEIPT_PREFIX = asm("OP_0 OP_RETURN")


def state_fields(root, value):
    return push(root) + push(value.to_bytes(RESULT_WIDTH, "little"))


def serialize_state(amount, *, prefix=b"", suffix=b""):
    # Given [encoded next, root], leave the complete serialized output.
    sample = Output(amount, prefix + state_fields(bytes(32), 0) + suffix).serialize()
    end = 32 + 1 + RESULT_WIDTH + len(suffix)
    code = push(sample[:-end]) + asm("OP_SWAP OP_CAT") + number(RESULT_WIDTH)
    code += asm("OP_CAT OP_SWAP OP_CAT")
    return code + push(suffix) + asm("OP_CAT") if suffix else code


def terminal_outputs(terminals):
    # Stack is [next, root, route]. Serialize the complete ordered output vector.
    review, settle = map(Output.serialize, terminals)
    return (asm("OP_IF") + push(settle) + asm("OP_ELSE")
            + push(review) + asm("OP_ENDIF OP_TOALTSTACK OP_SWAP")
            + number(RESULT_WIDTH) + asm("OP_NUM2BIN OP_SWAP")
            + serialize_state(0, prefix=RECEIPT_PREFIX)
            + asm("OP_FROMALTSTACK OP_SWAP OP_CAT"))


def terminal_check(decide, terminals):
    return asm("OP_OVER") + decide + terminal_outputs(terminals)


def root_txid(outpoint_offset=CURRENT_OUTPOINT):
    return copy_preimage() + field(outpoint_offset, 32)


def check_slot(index, outpoint_offset=CURRENT_OUTPOINT):
    return push(index) + check_field(outpoint_offset + 32, 4)


def check_siblings(index):
    # The ordered prevouts must be precisely slots zero and one of this input's parent.
    return (check_slot(index) + root_txid() + asm("OP_DUP") + push(ZERO_INDEX)
            + asm("OP_CAT OP_SWAP") + push(SIBLING_INDEX) + asm("OP_CAT OP_CAT OP_HASH256")
            + check_field(PREVOUTS_HASH))


def open_parent(outpoint_offset):
    # Stack is [raw parent, owner signature, committed root, committed next].
    # The first spend has one input and must have consumed slot zero of root.
    return (asm("OP_3 OP_PICK OP_DUP") + field(4, 1) + asm("OP_1 OP_EQUALVERIFY OP_DUP")
            + field(5, 36) + asm("OP_3 OP_PICK") + push(ZERO_INDEX) + asm("OP_CAT OP_EQUALVERIFY OP_HASH256")
            + push(ZERO_INDEX) + asm("OP_CAT") + check_field(outpoint_offset, 36))


def open_ancestry(depth, outpoint_offset):
    # Oldest parent first in the witness. Start at the authenticated prevout
    # and follow each single input in reverse until reaching the committed root.
    code = check_slot(ZERO_INDEX, outpoint_offset) + root_txid(outpoint_offset)
    one_parent = (asm("OP_4 OP_ROLL OP_DUP OP_HASH256 OP_ROT OP_EQUALVERIFY OP_DUP")
                  + field(4, 1) + asm("OP_1 OP_EQUALVERIFY OP_DUP")
                  + field(37, 4) + push(ZERO_INDEX) + asm("OP_EQUALVERIFY") + field(5, 32))
    return code + one_parent * depth + asm("OP_2 OP_PICK OP_EQUALVERIFY")


def sighash_blocker(workflow, mode, family):
    if family != "forkid" and (mode == "atomic" or workflow.recovery):
        message = ("Chronicle OTDA requires a single-input workflow" if mode == "atomic"
                   else "Chronicle OTDA with a recovery branch is unavailable")
        return {"code": "unsupported_sighash_context", "message": message}
    return None


def check_sighash_target(family, target):
    if family not in SIGHASH_FAMILY_OPTIONS:
        raise CompileError(f"unknown workflow sighash family {family!r}")
    if family != "forkid" and target == "forkid-v1":
        raise CompileError("Chronicle OTDA requires a Chronicle spend target")


class WorkflowContracts:
    def __init__(self, workflow, keys, current, *, mode="auto", target=DEFAULT_TARGET, optimization=BASELINE,
                 available_authorizers=None, context_layout=None, objective="path-bytes", max_tx_bytes=None,
                 sighash_family="forkid"):
        self.plan = plan_workflow(workflow, mode, available_authorizers=available_authorizers)
        self.current = input_value({workflow.input.name: current}, workflow.input.name)
        self.target, self.optimization = target, optimization
        self.versions, self.era = TARGETS[target]
        check_sighash_target(sighash_family, target)
        self.sighash_family = sighash_family
        self.dual_sighash = sighash_family == "both"
        self.sighash = FLAG if self.dual_sighash else SIGHASH_FAMILIES[sighash_family]
        if sighash_family == "chronicle":
            self.era = "chronicle"
        blocker = sighash_blocker(workflow, self.plan.mode, sighash_family)
        if blocker:
            raise CompileError(blocker["message"])
        self.version = self.versions[-1]
        self.templates = {template.name: template for template in self.plan.templates}
        self.keys = MappingProxyType(dict(keys))
        stage_roles = tuple(dict.fromkeys(stage.owner for stage in workflow.stages))
        roles = [*stage_roles, "review", "settle"]
        if workflow.recovery:
            roles.append(workflow.recovery.owner)
        for role in dict.fromkeys(roles):
            if not is_compressed_public_key(self.keys.get(role)):
                raise ValueError(f"workflow requires a compressed public key for {role}")
        if len({self.keys[role] for role in stage_roles}) != len(stage_roles):
            raise ValueError("distinct stage signers must have distinct public keys")
        if self.keys["review"] == self.keys["settle"]:
            raise ValueError("terminal scripts must be distinct")
        self.terminals = tuple(Output(TERMINAL_VALUE, p2pk(self.keys[role])) for role in ("review", "settle"))
        self.words = {stage.name: compile_word(stage.word, optimization) for stage in workflow.stages}
        linked = {}
        for template in self.plan.templates:
            # The state and terminal constructors commit every output in the indicated order.
            outputs = ("state",) if template.outputs == ("state",) else ("terminal", "receipt")
            # These predicates read the outpoint and state, and construct output amounts directly.
            context = LinkedContext.for_template(template, self.sighash, BINDING_CODE, outputs,
                                                 requires_previous_amount=False)
            if self.dual_sighash and context is not None:
                chronicle = LinkedContext.for_template(template, SIGHASH_FAMILIES["chronicle"], BINDING_CODE, outputs,
                                                       requires_previous_amount=False)
                context = DualLinkedContext(context, chronicle) if chronicle is not None else None
            if context is not None:
                linked[template.name] = context
        layouts = {"full": {}} if sighash_family == "forkid" else {}
        if sighash_family != "forkid" and len(linked) != len(self.plan.templates):
            raise CompileError("Chronicle OTDA requires known input and output commitments for every step")
        if linked:
            layouts["reconstructed"] = linked
        if context_layout is not None and context_layout not in layouts:
            raise ValueError(f"preimage layout {context_layout!r} is unavailable for {self.plan.mode}")
        self.context_options = {}
        for name in layouts if context_layout is None else (context_layout,):
            self.contexts = layouts[name]
            self.compile_locks()
            self.context_options[name] = estimate_cost(self)
        self.context_layout = min(self.context_options, key=lambda name: (
            max_tx_bytes is not None and self.context_options[name]["max_transaction_bytes"] > max_tx_bytes,
            candidate_rank(self.context_options[name], OBJECTIVES[objective]),
        ))
        if self.contexts is not layouts[self.context_layout]:
            self.contexts = layouts[self.context_layout]
            self.compile_locks()

    def compile_locks(self):
        workflow = self.plan.program
        first = workflow.stages[0]
        templates = self.plan.templates
        advance = number(self.current) + self.words[first.name].script
        decide = terminal_check(self.words[workflow.stages[-1].name].script, self.terminals)
        decide += self.output_check(templates[-1])
        if self.plan.mode == "atomic":
            self.deployment_outputs = self.atomic_outputs(advance, decide)
            self.root = self.deployment_outputs[0]
            return
        if self.plan.mode == "serial":
            self.state_codes = {}
            body = decide
            for depth in range(len(workflow.stages) - 1, 0, -1):
                stage = workflow.stages[depth]
                template = templates[depth]
                offset = self.outpoint_offset(template)
                if depth == 1:
                    opening = (open_parent(offset) + asm("OP_2SWAP") + self.authorize(self.keys[stage.owner])
                               + asm("OP_DROP"))
                else:
                    opening = (open_ancestry(depth, offset) + asm("OP_ROT")
                               + self.authorize(self.keys[stage.owner]))
                state_code = (asm("OP_DEPTH") + number(depth + 4) + asm("OP_NUMEQUALVERIFY OP_ROT")
                              + self.context_entry(template) + opening + asm("OP_BIN2NUM")
                              + validate_u32() + asm("OP_SWAP") + body + self.finish())
                producer = workflow.stages[depth - 1]
                amount = self.state_amount(depth)
                code = self.with_recovery(state_code, amount, prefixed=2)
                self.state_codes[producer.name] = amount, code
                if depth > 1:
                    body = (asm("OP_SWAP") + self.words[producer.name].script
                            + number(RESULT_WIDTH) + asm("OP_NUM2BIN OP_SWAP")
                            + self.commit_state(amount, code, templates[depth - 1]))
            self.state_code = self.state_codes[first.name][1]
            body = (number(RESULT_WIDTH) + asm("OP_NUM2BIN") + root_txid(self.outpoint_offset(templates[0]))
                    + self.commit_state(*self.state_codes[first.name], templates[0]))
        else:
            body = root_txid(self.outpoint_offset(templates[0])) + decide
        auth = templates[0].authorizers
        lock = (self.check_depth(len(auth) + 1) + self.context_entry(templates[0])
                + check_slot(ZERO_INDEX, self.outpoint_offset(templates[0]))
                + b"".join(self.authorize(self.keys[role]) for role in auth)
                + advance + body + self.finish())
        self.root = Output(ROOT_VALUE, self.with_recovery(lock, ROOT_VALUE))
        self.deployment_outputs = (self.root,)

    @staticmethod
    def check_depth(depth):
        return asm("OP_DEPTH") + number(depth) + asm("OP_NUMEQUALVERIFY")

    def authorize(self, public):
        return authorize(public, self.sighash, flag_script=COPY_LINKED_SIGHASH if self.dual_sighash else None)

    def finish(self):
        return finish(self.sighash, flag_script=asm("OP_FROMALTSTACK") if self.dual_sighash else None)

    def context_entry(self, template):
        context = self.contexts.get(template.name)
        if context is None:
            return begin(self.versions) + single_input()
        return (context.check_size() + asm("OP_DUP OP_TOALTSTACK")
                + field(0, 4) + check_version(self.versions))

    def outpoint_offset(self, template):
        return LINKED_OUTPOINT_OFFSET if template.name in self.contexts else CURRENT_OUTPOINT

    def output_check(self, template):
        context = self.contexts.get(template.name)
        return context.bind_outputs() if context else asm("OP_HASH256") + check_field(OUTPUTS_HASH)

    def state_amount(self, depth):
        stages = len(self.plan.program.stages)
        return ROOT_VALUE - ((ROOT_VALUE - TERMINAL_VALUE) * depth // stages)

    def commit_state(self, amount, code, template):
        return serialize_state(amount, suffix=code) + self.output_check(template)

    def with_recovery(self, lock, amount, *, prefixed=0):
        recovery = self.plan.program.recovery
        if recovery is None:
            return lock
        return recoverable_lock(lock, amount, self.keys[recovery.owner], recovery.height, self.versions,
                                prefixed=prefixed)

    def atomic_outputs(self, advance, decide):
        first, second = self.plan.program.stages
        # The first input checks the state. The second checks the route for that state.
        # Each commits the same root and state in the receipt and the route in output zero.
        route = (asm("OP_DUP OP_DUP OP_BIN2NUM OP_EQUALVERIFY OP_DUP OP_0 OP_2 OP_WITHIN OP_VERIFY"))
        first_lock = (self.check_depth(4) + begin(self.versions) + check_siblings(ZERO_INDEX) + authorize(self.keys[first.owner])
                      + asm("OP_OVER") + validate_u32() + advance + asm("OP_NUMEQUALVERIFY")
                      + route + root_txid() + asm("OP_SWAP") + terminal_outputs(self.terminals)
                      + asm("OP_HASH256") + check_field(OUTPUTS_HASH) + finish())
        second_lock = (self.check_depth(3) + begin(self.versions) + check_siblings(SIBLING_INDEX) + authorize(self.keys[second.owner])
                       + validate_u32() + root_txid() + decide + finish())
        return tuple(Output(value, self.with_recovery(lock, value))
                     for value, lock in ((STATE_VALUE, first_lock), (ROOT_VALUE - STATE_VALUE, second_lock)))

    def state_output(self, root, value, producer=None):
        producer = self.plan.program.stages[0].name if producer is None else producer
        amount, code = self.state_codes[producer]
        return Output(amount, state_fields(root, value) + code)

    @staticmethod
    def receipt(root, value):
        return Output(0, RECEIPT_PREFIX + state_fields(root, value))

    def spend_version(self, version):
        version = self.version if version is None else version
        if type(version) is not int or version not in self.versions:
            raise ValueError(f"transaction version {version} is unavailable for target {self.target}")
        return version

    def bound_state(self, completed, reference):
        root = completed.get("deploy")
        if (root is None or root.outputs[:len(self.deployment_outputs)] != self.deployment_outputs
                or root.version not in self.versions):
            raise ValueError("missing or mismatched workflow deployment")
        root_id = root.txid_wire()
        value, ancestor, ancestry = self.current, root, []
        if reference.step == "deploy":
            return UTXO(root, reference.vout), root_id, value, ()
        for stage in self.plan.program.stages[:-1]:
            parent = completed.get(stage.name)
            if parent is None or len(parent.inputs) != 1 or len(parent.outputs) != 1:
                raise ValueError(f"missing or malformed stage {stage.name}")
            if parent.inputs[0].outpoint() != Input(ancestor.txid_wire(), 0).outpoint() or parent.version not in self.versions:
                raise ValueError("intermediate output is from a different workflow root or parent")
            value, = evaluate(stage.word, value)
            if parent.outputs[0] != self.state_output(root_id, value, stage.name):
                raise ValueError("intermediate output does not carry the expected state")
            ancestry.append(parent)
            if stage.name == reference.step:
                return UTXO(parent, reference.vout), root_id, value, tuple(ancestry)
            ancestor = parent
        raise ValueError(f"unknown state output {reference.text()}")

    def prepare(self, name, completed, *, version=None, sighash_family=None):
        template = self.templates.get(name)
        if template is None:
            raise ValueError(f"unknown workflow step {name!r}")
        version = self.spend_version(version)
        sighash = self.sighash
        if sighash_family is not None:
            if (sighash_family not in SIGHASH_FAMILIES
                    or not (self.dual_sighash or sighash_family == self.sighash_family)):
                raise ValueError(f"sighash family {sighash_family!r} is unavailable for this spend")
            sighash = SIGHASH_FAMILIES[sighash_family]
        reference = template.inputs[0]
        utxo, root_id, value, ancestry = self.bound_state(completed, reference)
        previous = (utxo,)
        payload = (tuple(tx.serialize() for tx in ancestry),)
        roles = None
        stages = self.plan.program.stages
        if template.outputs == ("state",):
            stage = stages[len(ancestry)]
            value, = evaluate(stage.word, value)
            outputs = (self.state_output(root_id, value, stage.name),)
        else:
            if self.plan.mode != "serial":
                value, = evaluate(stages[0].word, value)
            route, = evaluate(stages[-1].word, value)
            outputs = (self.terminals[route], self.receipt(root_id, value))
            if self.plan.mode == "atomic":
                previous = (utxo, UTXO(utxo.parent, template.inputs[1].vout))
                payload = ((encode_num(value), encode_num(route)), (encode_num(value),))
                roles = self.input_authorizers(template)
        tx = Transaction(tuple(Input(item.outpoint.txid, item.vout) for item in previous), outputs, version=version)
        selector = False if self.plan.program.recovery else None
        context = self.contexts.get(name)
        return Draft(template, tx, previous, payload, self.keys, selector, roles,
                     context_encoder=context.pack if context else None, sighash=sighash)

    def prepare_refund(self, reference, completed, *, version=None):
        recovery = self.plan.program.recovery
        if reference not in self.recovery_refs():
            raise ValueError("no recovery branch for this workflow output")
        version = self.spend_version(version)
        utxo, _, _, _ = self.bound_state(completed, reference)
        template = Template("refund", (reference,), (recovery.owner,), ("refund",))
        txin = Input(utxo.outpoint.txid, utxo.vout, sequence=REFUND_SEQUENCE)
        output = refund_output(utxo.output.value, self.keys[recovery.owner])
        tx = Transaction((txin,), (output,), version=version, locktime=recovery.height)
        return Draft(template, tx, (utxo,), ((),), self.keys, True)

    @staticmethod
    def input_authorizers(template):
        return template.input_authorizers

    @classmethod
    def describe_templates(cls, plan):
        return [{**asdict(template), "input_authorizers": cls.input_authorizers(template)}
                for template in plan.templates]

    def recovery_refs(self):
        if self.plan.program.recovery is None:
            return ()
        return tuple(reference for step in self.plan.templates for reference in step.inputs)

    def recovery_status(self, completed, live_outpoints, *, tip_height):
        live = set(live_outpoints)
        bound = {ref: self.bound_state(completed, ref)[0] for ref in self.recovery_refs() if ref.step in completed}
        advance = [
            {"step": step.name, "authorizers": step.authorizers,
             "outpoints": [bound[ref].outpoint.text() for ref in step.inputs]}
            for step in self.plan.templates
            if all(ref in bound and bound[ref].outpoint in live for ref in step.inputs)
        ]
        refunds = []
        for ref, utxo in bound.items():
            if utxo.outpoint not in live:
                continue
            draft = self.prepare_refund(ref, completed)
            out, = draft.tx.outputs
            refunds.append({
                "input": utxo.outpoint.text(), "authorizer": draft.template.authorizers[0],
                "locktime": draft.tx.locktime, "eligible_next_block": tip_height + 1 > draft.tx.locktime,
                "output": {"vout": 0, "satoshis": out.value, "script_hex": out.script.hex()},
            })
        return {"tip_height": tip_height, "advance": advance, "refund": refunds}

    def artifact(self, source):
        def location(token):
            return {"line": token.line, "column": token.column}

        def output(item):
            return {"satoshis": item.value, "script_hex": item.script.hex()}

        workflow = self.plan.program
        graph = self.plan.graph.describe(recovery=workflow.recovery)
        spec = {
            "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schema_version": 1,
            "topology": "workflow", "schedule": self.plan.mode, "target": self.target, "era": self.era,
            "optimization": self.optimization, "supported_transaction_versions": self.versions,
            "transaction_version": self.version,
            "preimage_layout": {template.name: self.context_layout if template.name in self.contexts else "full"
                               for template in self.plan.templates},
            "input": {"name": workflow.input.name, "type": "u32", "value": self.current,
                      **location(workflow.input)},
            "stages": [{
                "name": stage.name, "word": stage.word.name, "authorizer": stage.owner,
                "input": {"name": stage.source.name, "type": stage.word.takes[0], **location(stage.source)},
                "output": {"name": stage.result.name, "type": stage.word.gives[0], **location(stage.result)},
                "source": location(stage.declaration),
            } for stage in workflow.stages],
            "dependencies": [edge for edge in graph["dependencies"] if edge["producer"] is not None],
            "transaction_graph": graph,
            "templates": self.describe_templates(self.plan),
            "deploy_output": output(self.root), "deployment_outputs": [output(item) for item in self.deployment_outputs],
            "boundary_reasons": self.plan.boundary_reasons,
            "terminal_outputs": {role: output(item) for role, item in zip(("review", "settle"), self.terminals)},
            "receipt": {"satoshis": 0, "script_prefix_hex": RECEIPT_PREFIX.hex(),
                        "fields": ("root txid in wire order", "u32 in five little-endian bytes")},
            "word_builds": {name: word.describe() for name, word in self.words.items()},
            "estimated_cost": estimate_cost(self),
        }
        if self.dual_sighash:
            context = self.contexts[self.plan.templates[0].name]
            spec["sighash_families"] = {
                name: {"flag": f"{flag:02x}", "packed_context_bytes": getattr(context, name).packed_bytes}
                for name, flag in SIGHASH_FAMILIES.items()
            }
            spec["default_sighash_family"] = "forkid"
            spec["estimated_cost"]["assumptions"]["sighash_family"] = "forkid"
        else:
            spec["sighash"] = f"{self.sighash:02x}"
        if workflow.libraries:
            spec["libraries"] = tuple(map(asdict, workflow.libraries))
        if self.plan.mode == "serial":
            spec["state_output"] = {"satoshis": self.state_amount(1), "script_suffix_hex": self.state_code.hex(),
                                    "fields": spec["receipt"]["fields"]}
            if len(self.state_codes) > 1:
                spec["state_outputs"] = {name: {"satoshis": amount, "script_suffix_hex": code.hex(),
                                              "fields": spec["receipt"]["fields"]}
                                         for name, (amount, code) in self.state_codes.items()}
        if workflow.recovery:
            spec["recovery"] = {
                **asdict(workflow.recovery), "sequence": REFUND_SEQUENCE,
                "refundable_outputs": [asdict(reference) for reference in self.recovery_refs()],
            }
        return build_artifact(spec, source)


def compile_workflow(workflow, keys, current, *, source_bytes, mode="auto", target=DEFAULT_TARGET,
                     optimization=BASELINE, available_authorizers=None, search=False, objective="path-bytes",
                     max_tx_bytes=None, sighash_family="forkid"):
    if mode not in ("auto", *WORKFLOW_MODES):
        raise CompileError("workflow mode must be fused, serial or atomic")
    if max_tx_bytes is not None and (not search or type(max_tx_bytes) is not int or max_tx_bytes <= 0):
        raise CompileError("a positive transaction byte budget requires search")
    check_sighash_target(sighash_family, target)
    roles = {stage.owner for stage in workflow.stages}
    available = roles if available_authorizers is None else set(available_authorizers)
    order = OBJECTIVES[objective]
    candidates, artifacts = {}, {}
    for layout in WORKFLOW_MODES:
        blockers = workflow_blockers(workflow, layout, available)
        sighash_exclusion = sighash_blocker(workflow, layout, sighash_family)
        if sighash_exclusion:
            blockers.append(sighash_exclusion)
        if blockers:
            plan = None if blockers[0]["code"] == "unsupported_stage_count" else workflow_layout(workflow, layout)
            candidates[layout] = {
                "eligible": False, "static_check": "excluded", "exclusions": blockers,
                "graph": WorkflowContracts.describe_templates(plan) if plan else [],
                "transaction_graph": plan.graph.describe(recovery=workflow.recovery) if plan else None,
                "boundary_reasons": plan.boundary_reasons if plan else (),
            }
            continue
        contract = WorkflowContracts(workflow, keys, current, mode=layout, target=target,
                                     optimization=optimization, available_authorizers=available,
                                     objective=objective, max_tx_bytes=max_tx_bytes, sighash_family=sighash_family)
        spec = contract.artifact(source_bytes)
        artifacts[layout] = spec
        cost = spec["estimated_cost"]
        if max_tx_bytes is not None and cost["max_transaction_bytes"] > max_tx_bytes:
            blockers = [{
                "code": "transaction_byte_budget", "limit": max_tx_bytes, "estimated": cost["max_transaction_bytes"],
                "message": f"largest estimated transaction is {cost['max_transaction_bytes']} B, "
                           f"above the {max_tx_bytes} B budget",
            }]
        candidates[layout] = {
            "eligible": not blockers, "static_check": "excluded" if blockers else "passed",
            "exclusions": blockers, "artifact_sha256": spec["artifact_sha256"], "graph": spec["templates"],
            "transaction_graph": spec["transaction_graph"],
            "deploy_output_count": len(spec["deployment_outputs"]),
            "preimage_candidates": {
                name: {"selected": name == contract.context_layout, "cost": cost}
                for name, cost in contract.context_options.items()
            },
            "boundary_reasons": spec["boundary_reasons"], "cost": cost, "rank": candidate_rank(cost, order),
        }
    eligible = [layout for layout, row in candidates.items() if row["eligible"]]
    if mode != "auto":
        selected, basis = mode, "explicit_request"
    elif not eligible:
        selected, basis = None, None
    elif search:
        selected = min(eligible, key=lambda layout: candidates[layout]["rank"])
        basis = "lowest_rank" if len(eligible) > 1 else "only_eligible_candidate"
    else:
        selected = next(layout for layout in WORKFLOW_MODES if layout in eligible)
        basis = "layout_preference" if len(eligible) > 1 else "only_eligible_candidate"
    if selected not in eligible:
        reasons = [f"{layout}: {blocker['message']}" for layout, row in candidates.items()
                   for blocker in row["exclusions"] if mode in ("auto", layout)]
        raise CompileError("no requested workflow layout is eligible (" + "; ".join(reasons) + ")")
    report = {
        "requested": mode, "selected": selected, "selection_basis": basis,
        "selected_artifact_sha256": artifacts[selected]["artifact_sha256"],
        "available_authorizers": sorted(available), "authorizers_defaulted": available_authorizers is None,
        "authorizer_availability_at": "first spend",
        "sighash_family": sighash_family,
        "search": search, "objective": objective if search else None,
        "rank_order": order if search else None, "max_transaction_bytes": max_tx_bytes, "candidates": candidates,
    }
    return artifacts[selected], report
