"""Generate a standard BLS12-381 .wtns with the Circom WASM ABI in Python."""

import argparse
import json
from pathlib import Path

from field import R


def _signal_hash(name):
    value = 0xCBF29CE484222325
    for byte in name.encode("ascii"):
        value = ((value ^ byte) * 0x100000001B3) & ((1 << 64) - 1)
    return value >> 32, value & 0xFFFFFFFF


def _flatten(value):
    if isinstance(value, (tuple, list)):
        for item in value:
            yield from _flatten(item)
    else:
        yield int(value)


def calculate_witness(wasm, signals):
    """Evaluate a Circom 2 witness generator with constraint assertions enabled."""
    import wasmtime

    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    module = wasmtime.Module.from_file(engine, str(wasm))
    linker = wasmtime.Linker(engine)
    errors = []

    def read_error(caller):
        read = caller.get("getMessageChar")
        message = []
        while char := read(caller):
            message.append(chr(char))
        errors.append("".join(message))

    def reject(code):
        detail = " ".join(errors)
        raise ValueError(f"Circom witness rejected with code {code} {detail}".rstrip())

    linker.define_func("runtime", "exceptionHandler", wasmtime.FuncType([wasmtime.ValType.i32()], []), reject)
    linker.define_func("runtime", "printErrorMessage", wasmtime.FuncType([], []), read_error, access_caller=True)
    for name in ("writeBufferMessage", "showSharedRWMemory"):
        linker.define_func("runtime", name, wasmtime.FuncType([], []), lambda: None)
    exports = linker.instantiate(store, module).exports(store)
    if exports["getVersion"](store) != 2 or exports["getFieldNumLen32"](store) != 8:
        raise ValueError("expected the Circom 2 BLS12-381 witness ABI")
    offset = exports["getSharedRWMemoryStart"](store)
    memory = exports["memory"]
    exports["getRawPrime"](store)
    if int.from_bytes(memory.read(store, offset, offset + 32), "little") != R:
        raise ValueError("Circom witness circuit uses a different scalar field")
    exports["init"](store, 1)

    count = 0
    for name, items in signals.items():
        high, low = _signal_hash(name)
        values = tuple(_flatten(items))
        if len(values) != exports["getInputSignalSize"](store, high, low):
            raise ValueError(f"incorrect Circom witness shape for signal {name}")
        for index, value in enumerate(values):
            memory.write(store, (value % R).to_bytes(32, "little"), offset)
            exports["setInputSignal"](store, high, low, index)
        count += len(values)
    if count != exports["getInputSize"](store):
        raise ValueError("incomplete Circom witness inputs")

    witness = []
    for index in range(exports["getWitnessSize"](store)):
        exports["getWitness"](store, index)
        witness.append(int.from_bytes(memory.read(store, offset, offset + 32), "little"))
    return witness


def main():
    from python_prover import write_witness

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    write_witness(args.out, calculate_witness(args.wasm, json.loads(args.inputs.read_text())))


if __name__ == "__main__":
    main()
