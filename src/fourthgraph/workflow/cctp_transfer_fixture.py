"""Build a 2-to-2 spend against the fixed CCTP archived test fixture.

The supplied signer receives (vin, digest, expected_owner) and returns canonical
DER without a sighash byte. The proof is reusable only for the exact archived
funding and ordered token parents. This module does not hold signing keys.
"""

from dataclasses import dataclass
from hashlib import sha256

from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der_canonize

from fourthgraph.bsv.pushtx import PUBLIC
from fourthgraph.bsv.script import asm, push, script_operations
from fourthgraph.bsv.transaction import Transaction, hash256, preimage_all
from fourthgraph.workflow.cctp_archive import OWNER_OFFSET, PAYMENTS, QUANTITY_OFFSET, inspect_archive, logical_model, read_archive
from fourthgraph.workflow.logical_cpn import validate_document


ARCHIVE_SHA256 = "822e47b420e0eab53a5808164196c17a507d09619e2fff8100b16c08058121c5"
COMPACT_SCRIPTCODE = push(PUBLIC) + asm("OP_CHECKSIG")


@dataclass(frozen=True)
class FixtureSpend:
    transaction: Transaction
    parents: tuple[Transaction, ...]
    cpn: dict


def _payload(operation):
    if operation[0] <= 75:
        return operation[1:]
    if operation[0] == 76:
        return operation[2:]
    raise ValueError("unexpected fixture push encoding")


def construct_fixture_spend(archive_path, model, payouts, signer):
    """Assemble a signed transaction for the first archived payment's inputs.

    Payouts are exactly two (positive u64 quantity, compressed owner key)
    pairs. The archived proof is reused with identical funding, ordered token
    outpoints and claims. All signatures are externally supplied.
    """
    archive, archive_digest = read_archive(archive_path)
    if archive_digest != ARCHIVE_SHA256:
        raise ValueError("this adapter requires the pinned CCTP test archive")
    graph = inspect_archive(archive, archive_sha256=archive_digest)
    if model != logical_model(graph):
        raise ValueError("logical CPN differs from the fixed archived graph")
    source = archive["transactions"]
    first_txid = archive["summary"]["transactions"][PAYMENTS[0]]["txid"]
    original = Transaction.parse(bytes.fromhex(source[first_txid]))
    parents = tuple(Transaction.parse(bytes.fromhex(source[item.txid[::-1].hex()])) for item in original.inputs)
    states = {row["id"]: row for row in graph["places"]}
    input_states = [states[f"{txin.txid[::-1].hex()}:{txin.vout}"]["token"] for txin in original.inputs[1:]]
    requested = tuple(payouts)
    if len(requested) != 2:
        raise ValueError("exactly two payouts are required")
    normalized = []
    for quantity, owner in requested:
        if type(quantity) is not int or not 0 < quantity < 1 << 64:
            raise ValueError("payout quantity must be a positive u64")
        if not isinstance(owner, bytes) or len(owner) != 33 or owner[0] not in (2, 3):
            raise ValueError("payout owner must be a compressed public key")
        VerifyingKey.from_string(owner, curve=SECP256k1)
        normalized.append((quantity, owner))
    if sum(quantity for quantity, _ in normalized) != sum(row["quantity"] for row in input_states):
        raise ValueError("token quantities do not balance")

    operations = tuple(script_operations(original.inputs[0].script))
    if len(operations) != 26 or any(len(item) != 49 or item[0] != 48 for item in operations[:22]):
        raise ValueError("archived verifier witness has an unexpected proof layout")
    prevouts = b"".join(item.outpoint() for item in original.inputs)
    funding = parents[0].outputs[original.inputs[0].vout]
    original_preimage = preimage_all(original, 0, funding.value, COMPACT_SCRIPTCODE)
    original_state = b"".join(output.script[QUANTITY_OFFSET:QUANTITY_OFFSET + 8]
                              + output.script[OWNER_OFFSET:OWNER_OFFSET + 33] for output in original.outputs)
    if (_payload(operations[-4]) != original_state or len(_payload(operations[-3])) != 156
            or _payload(operations[-2]) != prevouts or _payload(operations[-1]) != original_preimage):
        raise ValueError("archived verifier witness does not match its transaction")
    outputs = []
    for old, (quantity, owner) in zip(original.outputs, normalized, strict=True):
        script = (old.script[:QUANTITY_OFFSET] + quantity.to_bytes(8, "little")
                  + old.script[QUANTITY_OFFSET + 8:OWNER_OFFSET] + owner + old.script[OWNER_OFFSET + 33:])
        outputs.append(type(old)(old.value, script))
    transaction = Transaction(tuple(type(item)(item.txid, item.vout, sequence=item.sequence)
                                    for item in original.inputs), tuple(outputs),
                              version=original.version, locktime=original.locktime)
    successor_states = b"".join(quantity.to_bytes(8, "little") + owner for quantity, owner in normalized)
    preimage = preimage_all(transaction, 0, funding.value, COMPACT_SCRIPTCODE)
    witness = b"".join(operations[:22]) + push(successor_states) + operations[-3] + push(prevouts) + push(preimage)
    transaction = transaction.with_script(0, witness)
    for vin, state in enumerate(input_states, 1):
        previous = parents[vin].outputs[original.inputs[vin].vout]
        owner = bytes.fromhex(state["owner_compressed"])
        digest_to_sign = hash256(preimage_all(transaction, vin, previous.value, previous.script))
        signature = signer(vin, digest_to_sign, owner)
        if not isinstance(signature, bytes) or len(signature) != 70:
            raise ValueError(f"vin {vin}: fixture needs a 70-byte DER signature")
        try:
            r, s = sigdecode_der(signature, SECP256k1.order)
            key = VerifyingKey.from_string(owner, curve=SECP256k1)
            valid = (sigencode_der_canonize(r, s, SECP256k1.order) == signature
                     and key.verify_digest(signature, digest_to_sign, sigdecode=sigdecode_der))
        except (BadSignatureError, ValueError, AssertionError) as error:
            raise ValueError(f"vin {vin}: invalid owner signature") from error
        if not valid:
            raise ValueError(f"vin {vin}: invalid owner signature")
        preimage = preimage_all(transaction, vin, previous.value, COMPACT_SCRIPTCODE)
        transaction = transaction.with_script(vin, push(signature + b"\x41") + push(prevouts) + push(preimage))
    if len(transaction.serialize()) != 4075:
        raise ValueError("signed transaction does not have the archived circuit's fixed wire shape")

    original_transfer = next(item for item in model["transitions"] if item["name"] == PAYMENTS[0])
    input_places = {place["name"]: place for place in model["places"]}
    places = [{**input_places[arc["place"]], "initial": 1} for arc in original_transfer["inputs"]]
    output_arcs = []
    for slot, ((quantity, owner), output) in enumerate(zip(normalized, transaction.outputs, strict=True)):
        point = f"{transaction.txid()}:{slot}"
        places.append({"name": point, "type": "token", "initial": 0, "capacity": 1,
                       "metadata": {"carrier": "proposed-outpoint", "actual_outpoint": point,
                                    "satoshis": output.value, "script_sha256": sha256(output.script).hexdigest(),
                                    "token": {"quantity": quantity, "owner_compressed": owner.hex()}}})
        output_arcs.append({"name": f"vout:{slot}", "place": point, "type": "token"})
    transfer = {"name": PAYMENTS[0], "inputs": original_transfer["inputs"], "outputs": output_arcs,
                "metadata": {"actual_txid": transaction.txid(), "archive_sha256": ARCHIVE_SHA256,
                             "proof": "reused from fixed parent-opening fixture",
                             "status": "constructed; chain admission not established"}}
    result = validate_document({"schema_version": 1, "places": places, "transitions": [transfer]})
    if not result["ok"]:
        raise ValueError(f"constructed transfer CPN is invalid: {result['diagnostics']}")
    return FixtureSpend(transaction, parents, result["model"])
