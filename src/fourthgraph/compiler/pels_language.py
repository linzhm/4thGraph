"""Typed Forth words and build-time assertions for an exact PELS spend."""

from dataclasses import dataclass, replace

from fourthgraph.bsv.transaction import MAX_MONEY, Output
from fourthgraph.compiler.wordsets import Literal, PRIMITIVES, script_word


def compiler_only(*_):
    raise ValueError("PELS assertions require a transaction-aware lock build")


TX_OUTPUT = script_word("cell bytes", "output", None, Output, build_only=True)
INPUTS_EQUAL = script_word("cell", "cell", None, compiler_only, build_only=True)
OUTPUTS_EQUAL = script_word("cell", "cell", None, compiler_only, build_only=True)
TX_LOCKTIME = script_word("", "cell", None, compiler_only, build_only=True)
TX_PREVOUT_AMOUNT = script_word("", "cell", None, compiler_only, build_only=True)
WORDS = {"tx-output": TX_OUTPUT, "inputs=": INPUTS_EQUAL,
         "outputs=": OUTPUTS_EQUAL, "tx-locktime": TX_LOCKTIME, "tx-prevout-amount": TX_PREVOUT_AMOUNT}


@dataclass(frozen=True)
class TransactionField:
    name: str
    maximum: int


FIELDS = {id(TX_LOCKTIME): TransactionField("locktime", 0xffffffff),
          id(TX_PREVOUT_AMOUNT): TransactionField("previous_amount", MAX_MONEY)}


def output_assertion(instructions, stack, at):
    count = instructions[-1].instruction if instructions else None
    if (not isinstance(count, Literal) or count.kind != "cell"
            or not 1 <= count.value < len(stack)):
        raise at.error("outputs= needs a positive literal count and that many outputs")
    return replace(OUTPUTS_EQUAL, takes=("output",) * count.value + ("cell",))


@dataclass(frozen=True)
class Assertion:
    field: str
    expected: object
    source: tuple[str | None, int, int]


@dataclass(frozen=True)
class SpendConstraints:
    outputs: tuple[Output, ...]
    locktime: int | None
    previous_amount: int | None
    sources: tuple[tuple[str, tuple[str | None, int, int]], ...]


def read_constraints(block, at):
    """Evaluate concrete business expressions and retain the verified predicates."""
    from fourthgraph.compiler.source import LockBranch

    values = {}
    required = {}

    def verify(assertion, source):
        if isinstance(assertion, Assertion):
            if assertion.field in required:
                raise source.error(f"duplicate PELS assertion for {assertion.field}")
            required[assertion.field] = assertion
        elif type(assertion) is not int or assertion == 0:
            raise source.error("expected a true Forth value or a PELS assertion")

    def evaluate_step(step):
        node, source = step.node, step.source or at
        location = source.module, source.line, source.column
        args = tuple(values[key] for key in step.args)
        if isinstance(node, Literal):
            return (node.value,)
        if isinstance(node, LockBranch):
            flag = args[-1]
            if type(flag) is not int:
                raise source.error("PELS IF needs a build-time Forth flag")
            return evaluate_block(node.yes if flag else node.no)
        if node is TX_OUTPUT:
            output = Output(*args)
            try:
                output.serialize()
            except (TypeError, ValueError) as error:
                raise source.error("tx-output requires a valid satoshi amount and output script") from error
            return (output,)
        if node is INPUTS_EQUAL:
            if type(args[0]) is not int or args[0] != 1:
                raise source.error("this PELS lock needs exactly one input")
            return (Assertion("inputs", 1, location),)
        if getattr(node, "run", None) is OUTPUTS_EQUAL.run:
            return (Assertion("outputs", args[:-1], location),)
        if id(node) in FIELDS:
            return (FIELDS[id(node)],)
        if node is PRIMITIVES["="] and any(isinstance(value, TransactionField) for value in args):
            fact, expected = args if isinstance(args[0], TransactionField) else args[::-1]
            if type(expected) is not int or not 0 <= expected <= fact.maximum:
                raise source.error(f"{fact.name} requires a constant in [0, {fact.maximum}]")
            return (Assertion(fact.name, expected, location),)
        if node is PRIMITIVES["op_verify"]:
            verify(args[0], source)
            return ()
        if (node.location != "script" or node.requires_checksig
                or any(type(value) not in (bytes, int) for value in args)):
            raise source.error("PELS output expressions need build-time Forth values")
        try:
            return node.run(*args)
        except (TypeError, ValueError, ArithmeticError) as error:
            raise source.error(str(error)) from error

    def evaluate_block(block):
        for step in block.steps:
            values.update(zip(step.results, evaluate_step(step), strict=True))
        return tuple(values[key] for key in block.returns)

    flag, = evaluate_block(block)
    verify(flag, at)
    if "inputs" not in required or "outputs" not in required:
        raise at.error("a PELS lock must verify one input and the complete ordered outputs")
    facts = {key: assertion.expected for key, assertion in required.items()}
    locations = tuple(sorted((key, assertion.source) for key, assertion in required.items()))
    return SpendConstraints(facts["outputs"], facts.get("locktime"), facts.get("previous_amount"), locations)
