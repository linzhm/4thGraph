"""Lower a fixed-slot recursive edge to a backend-independent statement."""

from hashlib import sha256

from fourthgraph.compiler.source import CompileError, Shuffle, expanded
from fourthgraph.compiler.wordsets import HOST_WORDS, Literal, SHUFFLES
from fourthgraph.workflow.cpn import canonical


def lineage_statement(frontend, name):
    if name not in frontend.recursions:
        raise CompileError(f"unknown recursive predicate {name!r}")
    _, edge = frontend.recursions[name]
    word = frontend.words.get(edge.name)
    if word is None or (word.takes, word.gives) != (("transaction",), ("outpoint", "outpoint")):
        raise edge.error("recursive edge needs ( transaction -- outpoint outpoint )")
    stack = ["transaction"]
    projections = ("tx-input-prevout", "tx-output-outpoint")
    for operation, at in expanded(word.body):
        if isinstance(operation, Literal) and operation.kind == "cell":
            stack.append(operation.value)
        elif isinstance(operation, Shuffle):
            count, order, _ = SHUFFLES[operation.name]
            tail = stack[-count:]
            stack[-count:] = [tail[index] for index in order]
        elif at.name in projections and operation is HOST_WORDS[at.name]:
            slot = stack.pop()
            if stack.pop() != "transaction" or type(slot) is not int or not 0 <= slot < 2**32:
                raise at.error("a recursive edge requires a constant u32 transaction slot")
            stack.append((at.name, slot))
        else:
            raise at.error("unsupported operation in a fixed-slot recursive edge")
    if len(stack) != 2 or any(not isinstance(item, tuple) for item in stack):
        raise edge.error("recursive edge must return both endpoints")
    if tuple(item[0] for item in stack) != projections:
        raise edge.error("recursive edge must return the consumed outpoint before the new outpoint")
    document = {
        "predicate": name, "edge": edge.name, "input_slot": stack[0][1], "output_slot": stack[1][1],
        "public_inputs": ("issuance_outpoint", "rule_identity", "tip_outpoint"),
        "base": ("authorized_issuance", "tip_matches_issuance"),
        "step": ("valid_predecessor_proof", "same_issuance", "same_rule",
                 "predecessor_tip_matches_consumed_outpoint", "tip_matches_finalized_output"),
    }
    return {**document, "statement_sha256": sha256(canonical(document)).hexdigest()}
