"""Typed stage dependencies, symbolic transaction inputs, and their CPN projection."""

from collections import defaultdict, deque
from dataclasses import InitVar, asdict, dataclass


class CompileError(ValueError):
    pass


def location(token):
    result = {"line": token.line, "column": token.column}
    if token.module is not None:
        result["file"] = token.module
    return result


@dataclass(frozen=True)
class Port:
    name: str
    kind: str
    at: object
    linear: bool = False

    def describe(self):
        return {"name": self.name, "type": self.kind, "source": location(self.at)}


@dataclass(frozen=True)
class StageNode:
    name: str
    word: str
    authorizer: str | None
    takes: tuple[Port, ...]
    gives: tuple[Port, ...]
    at: object


@dataclass(frozen=True)
class Dependency:
    producer: str | None
    consumer: str
    value: Port

    def describe(self):
        return {"producer": self.producer, "consumer": self.consumer, "value": self.value.name,
                "type": self.value.kind, "source": location(self.value.at)}


@dataclass(frozen=True)
class StageGraph:
    inputs: tuple[Port, ...]
    stages: tuple[StageNode, ...]
    dependencies: tuple[Dependency, ...]

    @classmethod
    def build(cls, inputs, stages):
        producers = {port.name: (None, port) for port in inputs}
        for stage in stages:
            for port in stage.gives:
                if port.name in producers:
                    raise port.at.error(f"duplicate producer of {port.name!r}")
                producers[port.name] = stage.name, port
        used = set()
        dependencies, following = [], defaultdict(list)
        incoming = dict.fromkeys((stage.name for stage in stages), 0)
        for stage in stages:
            for port in stage.takes:
                if port.name not in producers:
                    raise port.at.error(f"no producer for {port.name!r}")
                producer, value = producers[port.name]
                if value.kind != port.kind:
                    raise port.at.error(f"{stage.word!r} needs {port.kind}, found {value.kind}")
                if value.linear and port.name in used:
                    raise port.at.error(f"illegal repeated consumption of {port.name!r}")
                used.add(port.name)
                dependencies.append(Dependency(producer, stage.name, port))
                if producer is not None:
                    following[producer].append(stage.name)
                    incoming[stage.name] += 1
        by_name = {stage.name: stage for stage in stages}
        ready = deque(name for name in incoming if incoming[name] == 0)
        ordered = []
        while ready:
            name = ready.popleft()
            ordered.append(by_name[name])
            for consumer in following[name]:
                incoming[consumer] -= 1
                if incoming[consumer] == 0:
                    ready.append(consumer)
        if len(ordered) != len(stages):
            for stage in stages:
                if incoming[stage.name]:
                    port = next(port for port in stage.takes if incoming.get(producers[port.name][0]))
                    raise port.at.error(f"dependency cycle at {port.at.text!r}")
        return cls(tuple(inputs), tuple(ordered), tuple(dependencies))

    def describe(self):
        return {
            "inputs": [{**port.describe(), "linear": port.linear} for port in self.inputs],
            "stages": [{
                "name": stage.name, "word": stage.word, "authorizer": stage.authorizer,
                "inputs": [port.describe() for port in stage.takes],
                "outputs": [{**port.describe(), "linear": port.linear} for port in stage.gives],
                "source": location(stage.at),
            } for stage in self.stages],
            "dependencies": [edge.describe() for edge in self.dependencies],
        }


@dataclass(frozen=True)
class ParentOutput:
    step: str
    vout: int

    def text(self):
        return f"{self.step}:{self.vout}"


@dataclass(frozen=True)
class Template:
    name: str
    inputs: tuple[ParentOutput, ...]
    authorizers: tuple[str, ...]
    outputs: tuple[str, ...]
    executes: tuple[str, ...] = ()

    @property
    def input_authorizers(self):
        if len(self.inputs) == 1:
            return (self.authorizers,)
        if not self.authorizers:
            return ((),) * len(self.inputs)
        if len(self.authorizers) != len(self.inputs):
            raise CompileError(f"{self.name}: expected one authorizer per input")
        return tuple((role,) for role in self.authorizers)


@dataclass(frozen=True)
class TransactionGraph:
    stages: StageGraph
    deployment_outputs: tuple[str, ...]
    templates: tuple[Template, ...]
    executable: InitVar[bool] = True

    def __post_init__(self, executable):
        outputs = {"deploy": self.deployment_outputs}
        ancestors = {"deploy": set()}
        stages = {stage.name: stage for stage in self.stages.stages}
        prerequisites = defaultdict(list)
        for edge in self.stages.dependencies:
            if edge.producer is not None:
                prerequisites[edge.consumer].append(edge.producer)
        executed = {}
        consumed = set()
        for template in self.templates:
            if template.name in outputs or not template.inputs or not template.outputs:
                raise CompileError(f"invalid or duplicate transaction step {template.name!r}")
            authorizers = tuple(owner for roles in template.input_authorizers for owner in roles)
            parents = set()
            at = next((stages[name].at for name in template.executes if name in stages), None)
            for ref in template.inputs:
                if ref.step not in outputs or not 0 <= ref.vout < len(outputs[ref.step]):
                    message = f"{template.name}: no preceding output {ref.text()}"
                    raise at.error(message) if at else CompileError(message)
                if outputs[ref.step][ref.vout] in {"receipt", "data"}:
                    message = f"{template.name}: cannot spend data output {ref.text()}"
                    raise at.error(message) if at else CompileError(message)
                if ref in consumed:
                    message = f"{template.name}: illegal repeated consumption of {ref.text()}"
                    raise at.error(message) if at else CompileError(message)
                consumed.add(ref)
                parents.add(ref.step)
                parents.update(ancestors[ref.step])
            for name in template.executes:
                if name == "split":
                    continue  # Infrastructure step in the legacy template representation.
                if name not in stages or name in executed:
                    raise CompileError(f"{template.name}: invalid or duplicate stage execution {name!r}")
                stage = stages[name]
                if executable and stage.authorizer is not None and stage.authorizer not in authorizers:
                    raise stage.at.error(f"{template.name}: missing authorizer {stage.authorizer!r}")
                for producer in prerequisites[name]:
                    owner = executed.get(producer)
                    if owner != template.name and owner not in parents:
                        raise stage.at.error(f"{template.name}: does not depend on producer {producer!r}")
                executed[name] = template.name
            outputs[template.name] = template.outputs
            ancestors[template.name] = parents
        if missing := stages.keys() - executed.keys():
            name = min(missing)
            raise stages[name].at.error(f"no transaction executes stage {name!r}")

    def describe(self, *, recovery=None, external_inputs=lambda _: ()):
        steps = [{
            "step": "deploy", "inputs": [], "outputs": self.describe_outputs("deploy", self.deployment_outputs),
            "executes": [], "external_inputs": [],
        }]
        refunds = []
        output_kinds = {"deploy": self.deployment_outputs}
        for template in self.templates:
            inputs = [{"from": asdict(ref), "authorizers": owners}
                      for ref, owners in zip(template.inputs, template.input_authorizers, strict=True)]
            kinds = tuple(output_kinds[ref.step][ref.vout] for ref in template.inputs)
            guards = ["actual-prevouts", "actual-successors"]
            if template.authorizers:
                guards.append("input-authorizations")
            if kinds == ("result", "result"):
                guards.append("ordered-results-from-one-split")
            if kinds == ("state-lock", "route-lock"):
                guards.append("ordered-siblings-from-one-deployment")
            if kinds == ("state",):
                guards.append("ancestry-to-deploy")
            steps.append({
                "step": template.name, "inputs": inputs, "outputs": self.describe_outputs(template.name, template.outputs),
                "executes": [name for name in template.executes if name != "split"],
                "external_inputs": external_inputs(template),
                "guards": guards,
            })
            output_kinds[template.name] = template.outputs
            if recovery is not None:
                refunds.extend({
                    "step": f"refund/{ref.text()}", "from": asdict(ref), "conflicts_with": template.name,
                    "authorizer": recovery.owner, "locktime": recovery.height,
                    "output": self.describe_outputs(f"refund/{ref.text()}", ("refund",))[0],
                } for ref in template.inputs)
        return {"schema_version": 1, **self.stages.describe(), "transactions": steps, "refunds": refunds,
                "utxo_token_fields": ("txid:vout", "satoshis", "locking_script")}

    @staticmethod
    def describe_outputs(step, outputs):
        return [{"vout": index, "kind": kind, "place": ParentOutput(step, index).text(),
                 "spendable": kind not in {"data", "receipt"}}
                for index, kind in enumerate(outputs)]


def mermaid(graph):
    """Render the UTXO places and transitions of one selected graph."""
    lines = ["flowchart LR"]
    places = {}
    for index, tx in enumerate(graph["transactions"]):
        transition = f"T{index}"
        label = tx["step"]
        if tx["executes"] and tx["executes"] != [label]:
            label += " · " + ", ".join(tx["executes"])
        lines.append(f'    {transition}["{label}"]')
        for item in tx["inputs"]:
            ref = ParentOutput(**item["from"])
            arc = f' -->|{", ".join(item["authorizers"])}| ' if item["authorizers"] else " --> "
            lines.append(f"    {places[ref.text()]}{arc}{transition}")
        for output in tx["outputs"]:
            place = f"P{index}_{output['vout']}"
            places[output["place"]] = place
            label = f"{output['place']} · {output['kind']}"
            lines.append(f'    {transition} --> {place}(("{label}"))')
    for index, refund in enumerate(graph["refunds"]):
        ref = ParentOutput(**refund["from"])
        label = f"refund · {refund['authorizer']} · locktime {refund['locktime']}"
        lines.append(f'    {places[ref.text()]} --> R{index}["{label}"]')
        lines.append(f'    R{index} --> RP{index}(("{refund["output"]["place"]}"))')
    return "\n".join(lines)
