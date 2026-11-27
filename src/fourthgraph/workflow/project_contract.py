"""Host side of the project contract ABI. Manifest approvals are supplied by the local caller."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess

from fourthgraph.bsv.artifacts import script_listing
from fourthgraph.bsv.script import without_codeseparators
from fourthgraph.bsv.transaction import Input, hash256, preimage_forkid, preimage_otda


ABI = "4thgraph.project-contract/1"
SETTLEMENT_FIELDS = ("version", "outpoint", "sequence", "outputs", "locktime")


class ContractError(ValueError):
    def __init__(self, status, detail):
        self.status = status
        super().__init__(detail)


def wire_tx(tx):
    return {"version": tx.version, "locktime": tx.locktime,
            "inputs": [{"outpoint": i.outpoint().hex(), "script": i.script.hex(), "sequence": i.sequence} for i in tx.inputs],
            "outputs": [{"lock": o.script.hex(), "amount": o.value} for o in tx.outputs]}


def checked_file(root, entry):
    path = (root / entry["file"]).resolve()
    if not path.is_relative_to(root) or sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise ContractError("UnapprovedArtifact", "file outside package or digest mismatch")
    return path


class ProjectContract:
    def __init__(self, manifest, approved_digest):
        path = Path(manifest).resolve()
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != approved_digest:
            raise ContractError("UnapprovedManifest", "manifest differs from local approval")
        self.digest = approved_digest
        self.package = json.loads(raw)
        if self.package["abi"] != ABI:
            raise ContractError("UnsupportedABI", "unknown project contract ABI")
        self.module = checked_file(path.parent, self.package["module"])
        self.template = checked_file(path.parent, self.package["script"]).read_bytes()
        self.slots = sorted((s["offset"], s["offset"]+s["length"]) for s in self.package["parameters"])
        end = 0
        for start, stop in self.slots:
            if not end <= start < stop <= len(self.template):
                raise ContractError("InvalidManifest", "overlapping or out-of-range parameter layout")
            end = stop
        boundaries = {0} | {row["offset"]+1 for row in script_listing(self.template) if row["op"]=="OP_CODESEPARATOR"}
        for rule in self.package["paths"].values():
            offset = rule["script_code_offset"]
            mode = rule["mode"]
            if offset not in boundaries or rule["signatures"] not in (0, 1) or mode not in (0x41, 0x61):
                raise ContractError("InvalidManifest", "path has invalid signature anchor or unsupported coverage")
            if "witness_layout" in rule or mode == 0x61:
                fields = list(SETTLEMENT_FIELDS) + (["previous_amount"] if mode == 0x41 else [])
                code = self.template[offset:]
                if mode == 0x61:
                    code = without_codeseparators(code)
                if (self.slots or rule.get("witness_layout") != "reconstructed" or rule["signatures"] != 0
                        or rule.get("requires_chronicle") is not (mode == 0x61)
                        or rule.get("authenticated_fields") != fields
                        or rule.get("script_code_sha256") != sha256(code).hexdigest()):
                    raise ContractError("InvalidManifest", "linked path metadata contradicts the approved coverage")
        for field in ("listing", "fixtures"):
            checked_file(path.parent, self.package[field])

    def call(self, method, request):
        if method not in ("recognize","prepare_spend","assemble_unlock"):
            raise ContractError("InvalidRequest", "unknown ABI entry")
        runner = Path(__file__).with_name("contract_runtime.mjs")
        try:
            proc = subprocess.run(["node", "--no-warnings", str(runner), str(self.module),
                                   self.package["module"]["sha256"], method], input=json.dumps(request),
                                  capture_output=True, text=True, check=True, timeout=15)
            return json.loads(proc.stdout)
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            raise ContractError("ModuleFailure", f"{method}: {exc}") from exc

    def matches(self, lock):
        if len(lock) != len(self.template):
            return False
        end = 0
        for start, stop in self.slots:
            if lock[end:start] != self.template[end:start]:
                return False
            end = stop
        return lock[end:] == self.template[end:]

    def recognize(self, parent, vout, pubkey=b""):
        if not 0 <= vout < len(parent.outputs):
            raise ContractError("MissingContext", "prevout index absent from parent")
        output = parent.outputs[vout]
        if not self.matches(output.script):
            return {"status":"NoMatch"}
        return self.call("recognize", {"prevout":{"outpoint":Input(parent.txid_wire(), vout).outpoint().hex(),
                                                 "amount":output.value, "lock":output.script.hex()}, "pubkey":pubkey.hex()})

    def request(self, parent, tx, index, path, pubkey=b""):
        if not 0 <= index < len(tx.inputs):
            raise ContractError("CandidateMismatch", "invalid input index")
        txin = tx.inputs[index]
        if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
            raise ContractError("CandidateMismatch", "actual parent does not fund the selected input")
        prev = parent.outputs[txin.vout]
        return {"prevout": {"outpoint": txin.outpoint().hex(), "lock": prev.script.hex(), "amount": prev.value},
                "pubkey": pubkey.hex(), "transaction": wire_tx(tx), "input_index": index, "path": path}

    def prepare(self, parent, tx, index, path, pubkey=b""):
        request = self.request(parent, tx, index, path, pubkey)
        if not self.matches(parent.outputs[tx.inputs[index].vout].script):
            raise ContractError("NoMatch", "actual prevout differs from the approved template")
        rule = self.package["paths"].get(path)
        if rule is None:
            raise ContractError("UnsupportedPath", "path missing from approved manifest")
        result = self.call("prepare_spend", request)
        if result["status"] != "Prepared":
            raise ContractError(result["status"], result.get("detail", "preparation failed"))
        prev = parent.outputs[tx.inputs[index].vout]
        code = prev.script[rule["script_code_offset"]:]
        preimage = (preimage_otda(tx, index, without_codeseparators(code), rule["mode"])
                    if rule["mode"] == 0x61 else preimage_forkid(tx, index, prev.value, code, rule["mode"]))
        expected = {"candidate": sha256(tx.serialize()).hexdigest(), "outpoint": tx.inputs[index].outpoint().hex(),
                    "input_index": index, "path": path, "mode": rule["mode"], "preimage": preimage.hex(),
                    "digest": hash256(preimage).hex()}
        if tx.inputs[index].script or result["prepared"] != expected:
            raise ContractError("CandidateMismatch", "module signing materials differ from host computation")
        return expected

    def spend(self, parent, tx, index, path, pubkey, authorize, verify):
        """Authorize this concrete candidate, then independently check the completed transaction."""
        prepared = self.prepare(parent, tx, index, path, pubkey)
        rule = self.package["paths"][path]
        # A signer can inspect the full immutable candidate/parent, path and coverage before approving.
        signatures = [] if rule["signatures"] == 0 else [authorize(parent, tx, index, path, bytes.fromhex(prepared["digest"])).hex()]
        request = {**self.request(parent, tx, index, path, pubkey), "prepared": prepared, "authorizations": signatures}
        result = self.call("assemble_unlock", request)
        if result["status"] != "Assembled":
            raise ContractError(result["status"], result.get("detail", "assembly failed"))
        signed = tx.with_script(index, bytes.fromhex(result["unlock"]))
        if not verify(signed):
            raise ContractError("VerificationFailed", "independent verification rejected the spend")
        return signed
