"""Synthetic signed transaction workloads used by the project benchmarks."""
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import new, sha256
from itertools import product
from pathlib import Path

from .script import push
from .transaction import Input, Output, Transaction, hash256, preimage_forkid, preimage_otda

MODES = (0x41, 0x61)
SHAPES = ((2, 2), (3, 2), (2, 3))
FEE = 100


@dataclass(frozen=True)
class Coin:
    output: Output
    unlock: Callable[[Transaction, int, Transaction, int, Path], Transaction]
    activated: "Coin | None" = None


@dataclass(frozen=True)
class Template:
    create: Callable[[str, int], Coin]
    deferred: bool = False


@dataclass(frozen=True)
class Leg:
    tx: Transaction
    parents: tuple[Transaction, ...]  # One parent per input, in input order.
    flags: tuple[int, ...]


def seed(label):
    return sha256(("script-lab benchmark test only/" + label).encode()).digest()


def native_coin(label, value, *, p2pk=False):
    from ecdsa import SECP256k1, SigningKey
    from ecdsa.util import sigencode_der_canonize

    scalar = 1 + int.from_bytes(seed(label), "big") % (SECP256k1.order - 1)
    key = SigningKey.from_secret_exponent(scalar, curve=SECP256k1)
    public = key.get_verifying_key().to_string("compressed")
    owner = new("ripemd160", sha256(public).digest()).digest()
    lock = push(public) + b"\xac" if p2pk else b"\x76\xa9" + push(owner) + b"\x88\xac"

    def unlock(tx, index, parent, flag, _scratch):
        previous = parent.outputs[tx.inputs[index].vout]
        if flag & 0x20:
            preimage = preimage_otda(tx, index, previous.script, flag)
        else:
            preimage = preimage_forkid(tx, index, previous.value, previous.script, flag)
        signature = key.sign_digest_deterministic(
            hash256(preimage), hashfunc=sha256, sigencode=sigencode_der_canonize,
        )
        witness = push(signature + bytes([flag]))
        return tx.with_script(index, witness if p2pk else witness + push(public))

    return Coin(Output(value, lock), unlock)


def synthetic_parent(label, coin):
    return Transaction((Input(seed(label), 0),), (coin.output,))


def payment(sources, destinations, scratch, *, fee=FEE):
    """Sign each (parent, vout, coin, sighash) against the same transaction intent."""
    parents, indices, coins, flags = zip(*sources, strict=True)
    tx = Transaction(tuple(Input(parent.txid_wire(), index)
                           for parent, index in zip(parents, indices, strict=True)),
                     tuple(coin.output for coin in destinations))
    for index, (parent, vout, coin, flag) in enumerate(sources):
        if parent.outputs[vout] != coin.output:
            raise ValueError("benchmark coin does not match its previous output")
        signed = coin.unlock(tx, index, parent, flag, scratch)
        witness = signed.inputs[index].script
        if not witness or signed != tx.with_script(index, witness):
            raise ValueError("benchmark signer changed the transaction intent")
        tx = signed
    paid = sum(parent.outputs[vout].value for parent, vout, *_ in sources)
    if paid - sum(out.value for out in tx.outputs) != fee:
        raise ValueError("inconsistent fixture fee")
    return Leg(tx, parents, flags)


def allocations(value, count):
    each, remainder = divmod(value, count)
    return [each + (index < remainder) for index in range(count)]


def activation(sources, mode, label, scratch, extra_output=None):
    destinations = [coin.activated for _, _, coin in sources]
    if any(coin is None for coin in destinations):
        raise ValueError("missing activation target")
    extra_value = extra_output.output.value if extra_output else 0
    sponsor = native_coin(label + "/sponsor", FEE + extra_value)
    sponsor_parent = synthetic_parent(label + "/sponsor", sponsor)
    inputs = [(parent, index, coin, mode) for parent, index, coin in sources]
    if extra_output:
        destinations.append(extra_output)
    return (payment([*inputs, (sponsor_parent, 0, sponsor, 0x41)], destinations, scratch),
            destinations)


def batch(template, mode, shape, label, scratch):
    inputs, outputs = shape
    funded = [template.create(f"{label}/input/{i}", 10_000) for i in range(inputs)]
    sources = [(synthetic_parent(f"{label}/input/{i}", coin), 0, coin)
               for i, coin in enumerate(funded)]
    if template.deferred:
        extra = template.create(f"{label}/extra", 10_000).activated if outputs > inputs else None
        return activation(sources, mode, label, scratch, extra_output=extra)[0]
    values = allocations(inputs * 10_000 - FEE, outputs)
    destinations = [template.create(f"{label}/output/{i}", value) for i, value in enumerate(values)]
    return payment([(*source, mode) for source in sources], destinations, scratch)


def lifecycle(template, mode, turnover, label, scratch):
    coins = [template.create(f"{label}/deposit/{i}", 10_000) for i in range(2)]
    source = native_coin(label + "/source", 20_000 + FEE)
    parent = synthetic_parent(label + "/source", source)
    legs = {"funding": payment([(parent, 0, source, 0x41)], coins, scratch)}
    current = legs["funding"].tx
    if template.deferred:
        legs["activation"], coins = activation(
            [(current, i, coin) for i, coin in enumerate(coins)], mode, label, scratch,
        )
        current = legs["activation"].tx
    phases = ("turnover", "exit") if turnover else ("exit",)
    for phase in phases:
        values = allocations(sum(coin.output.value for coin in coins) - FEE, 2)
        create = native_coin if phase == "exit" else template.create
        destinations = [create(f"{label}/{phase}/{i}", value) for i, value in enumerate(values)]
        if phase == "turnover" and template.deferred:
            destinations = [coin.activated for coin in destinations]
        legs[phase] = payment([(current, i, coin, mode) for i, coin in enumerate(coins)],
                              destinations, scratch)
        current, coins = legs[phase].tx, destinations
    return legs


def batch_shapes(template):
    if template.deferred:
        # An extra activation always requires its matching output. An extra
        # output alone also requires a sponsor that covers its value.
        return ((2, 2), (3, 3), (2, 3))
    return SHAPES


def workloads(template, name, scratch):
    for mode, (inputs, outputs) in product(MODES, batch_shapes(template)):
        label = f"{name}/{mode:02x}/batch/{inputs}x{outputs}"
        yield label, {"payment": batch(template, mode, (inputs, outputs), label, scratch)}
    for mode, turnover in product(MODES, (False, True)):
        scenario = "turnover" if turnover else "direct-exit"
        label = f"{name}/{mode:02x}/{scenario}"
        yield label, lifecycle(template, mode, turnover, label, scratch)
