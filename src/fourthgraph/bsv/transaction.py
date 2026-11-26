"""Legacy BSV transaction wire format and ForkID and OTDA sighash preimages."""
from dataclasses import dataclass, replace
from hashlib import sha256


def hash256(b): return sha256(sha256(b).digest()).digest()

def compact(n):
    if not 0<=n<=0xffffffffffffffff: raise ValueError('CompactSize range')
    return bytes([n]) if n<253 else b'\xfd'+n.to_bytes(2,'little') if n<=65535 else b'\xfe'+n.to_bytes(4,'little') if n<=0xffffffff else b'\xff'+n.to_bytes(8,'little')

def blob(b): return compact(len(b))+b

def amount(n):
    if type(n) is not int or not 0<=n<=2_100_000_000_000_000: raise ValueError('invalid satoshi amount')
    return n.to_bytes(8,'little')


@dataclass(frozen=True)
class Input:
    txid: bytes  # 32 bytes in wire (little-endian) order
    vout: int
    script: bytes = b''
    sequence: int = 0xffffffff
    def outpoint(self):
        if len(self.txid)!=32: raise ValueError('txid must have 32 bytes')
        return self.txid+self.vout.to_bytes(4,'little')
    def serialize(self): return self.outpoint()+blob(self.script)+self.sequence.to_bytes(4,'little')


@dataclass(frozen=True)
class Output:
    value: int
    script: bytes
    def serialize(self): return amount(self.value)+blob(self.script)


@dataclass(frozen=True)
class Transaction:
    inputs: tuple[Input,...]
    outputs: tuple[Output,...]
    version: int = 2
    locktime: int = 0
    def serialize(self):
        return self.version.to_bytes(4,'little')+compact(len(self.inputs))+b''.join(x.serialize() for x in self.inputs)+compact(len(self.outputs))+b''.join(x.serialize() for x in self.outputs)+self.locktime.to_bytes(4,'little')
    def txid_wire(self): return hash256(self.serialize())
    def txid(self): return self.txid_wire()[::-1].hex()
    def with_script(self,index,script):
        inputs=list(self.inputs); inputs[index]=replace(inputs[index],script=script)
        return replace(self,inputs=tuple(inputs))
    @classmethod
    def parse(cls,raw):
        cursor=0
        def take(n):
            nonlocal cursor
            if n<0 or cursor+n>len(raw): raise ValueError('truncated transaction')
            result=raw[cursor:cursor+n]; cursor+=n; return result
        def integer(n): return int.from_bytes(take(n),'little')
        def count():
            lead=integer(1)
            if lead<253: return lead
            size={253:2,254:4,255:8}[lead]; value=integer(size)
            if value<({2:253,4:65536,8:4294967296}[size]): raise ValueError('noncanonical CompactSize')
            return value
        version=integer(4)
        inputs=tuple(Input(take(32),integer(4),take(count()),integer(4)) for _ in range(count()))
        outputs=tuple(Output(integer(8),take(count())) for _ in range(count()))
        locktime=integer(4)
        if cursor!=len(raw): raise ValueError('trailing transaction data')
        result=cls(inputs,outputs,version,locktime)
        if result.serialize()!=raw: raise ValueError('noncanonical transaction')
        return result


SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE = 1, 2, 3
FORKID, CHRONICLE, ANYONECANPAY = 0x40, 0x20, 0x80
FORKID_TYPES = frozenset(FORKID | base | flags for base in (1, 2, 3) for flags in (0, ANYONECANPAY))
OTDA_TYPES = frozenset(flag | CHRONICLE for flag in FORKID_TYPES)
SIGHASH_TYPES = FORKID_TYPES | OTDA_TYPES


def preimage_forkid(tx, index, previous_amount, script_code, sighash):
    if sighash not in FORKID_TYPES or not 0 <= index < len(tx.inputs):
        raise ValueError('invalid ForkID sighash or input index')
    base = sighash & 31
    anyone = sighash & ANYONECANPAY
    current = tx.inputs[index]
    prevouts = sequences = outputs = bytes(32)
    if not anyone:
        prevouts = hash256(b''.join(x.outpoint() for x in tx.inputs))
        if base == SIGHASH_ALL:
            sequences = hash256(b''.join(x.sequence.to_bytes(4, 'little') for x in tx.inputs))
    if base == SIGHASH_ALL:
        outputs = hash256(b''.join(x.serialize() for x in tx.outputs))
    elif base == SIGHASH_SINGLE and index < len(tx.outputs):
        outputs = hash256(tx.outputs[index].serialize())
    return (tx.version.to_bytes(4, 'little') + prevouts + sequences + current.outpoint() +
            blob(script_code) + amount(previous_amount) + current.sequence.to_bytes(4, 'little') +
            outputs + tx.locktime.to_bytes(4, 'little') + sighash.to_bytes(4, 'little'))


def preimage_all(tx, index, previous_amount, script_code=b'\xac'):
    return preimage_forkid(tx, index, previous_amount, script_code, FORKID | SIGHASH_ALL)


def preimage_otda(tx, index, script_code, sighash):
    """Serialize OTDA with a caller-supplied, already cleaned scriptCode."""
    if sighash not in OTDA_TYPES or not 0 <= index < len(tx.inputs):
        raise ValueError('invalid OTDA sighash or input index')
    base = sighash & 31
    if base == SIGHASH_SINGLE and index >= len(tx.outputs):
        raise ValueError('unpaired OTDA SINGLE has no transaction preimage')
    inputs = (index,) if sighash & ANYONECANPAY else range(len(tx.inputs))
    serialized_inputs = []
    for i in inputs:
        txin = tx.inputs[i]
        script = script_code if i == index else b''
        sequence = txin.sequence if i == index or base == SIGHASH_ALL else 0
        serialized_inputs.append(txin.outpoint() + blob(script) + sequence.to_bytes(4, 'little'))
    if base == SIGHASH_NONE:
        outputs = ()
    elif base == SIGHASH_SINGLE:
        outputs = (b'\xff'*8 + b'\0',)*index + (tx.outputs[index].serialize(),)
    else:
        outputs = tuple(output.serialize() for output in tx.outputs)
    return (tx.version.to_bytes(4, 'little') + compact(len(inputs)) + b''.join(serialized_inputs) +
            compact(len(outputs)) + b''.join(outputs) + tx.locktime.to_bytes(4, 'little') +
            sighash.to_bytes(4, 'little'))
