"""Independent complete-transaction engine adapter, plus a development checker."""
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigdecode_der
from tx_engine import Script, Tx, TxIn, TxOut
from script import COMPANION_CODE, ORDINARY_CODE
from shared.transaction import CHRONICLE, SIGHASH_SINGLE, SIGHASH_TYPES, hash256, preimage_forkid, preimage_otda
from shared.evaluate import evaluate, ScriptError


def native_checker(tx, index, amount, *, legacy=True, companion=False):
    def check(signature, key):
        flag = signature[-1]
        if flag not in SIGHASH_TYPES:
            return False
        code = b'\xac' if legacy else COMPANION_CODE if companion else ORDINARY_CODE
        if flag & CHRONICLE:
            if flag & 31 == SIGHASH_SINGLE and index >= len(tx.outputs):
                digest = b'\x01'+bytes(31)
            else:
                code = code.replace(b'\xab', b'')  # known suffixes contain no pushes
                digest = hash256(preimage_otda(tx,index,code,flag))
        else:
            digest = hash256(preimage_forkid(tx,index,amount,code,flag))
        try:
            return VerifyingKey.from_string(key,curve=SECP256k1).verify_digest(signature[:-1],digest,sigdecode=sigdecode_der)
        except (BadSignatureError,ValueError): return False
    return check


def development_valid(tx, parent, index):
    # All test fixtures use output zero; bad vout cases still test the same prevout.
    previous = parent.outputs[0]
    try:
        witness, _ = evaluate(tx.inputs[index].script)
        checker = native_checker(tx,index,previous.value,legacy=len(witness)==2,
                                 companion=len(witness)==3 and witness[-1]==b'\x01')
        stack, alt = evaluate(previous.script,witness,checker)
        return stack == [b'\x01'] and alt == []
    except ScriptError: return False


def engine_script(raw):
    script = Script()
    script.append_data(raw)
    return script


def engine_tx(tx):
    result = Tx(tx.version,[TxIn(x.txid[::-1].hex(),x.vout,engine_script(x.script),x.sequence) for x in tx.inputs],
                [TxOut(x.value,engine_script(x.script)) for x in tx.outputs],tx.locktime)
    if result.serialize() != tx.serialize(): raise AssertionError('serializer mismatch')
    return result


def chain_valid(tx, parents):
    try:
        engine_tx(tx).validate([engine_tx(p) for p in parents])
        return True
    except (RuntimeError, ValueError): return False
