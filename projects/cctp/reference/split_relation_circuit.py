"""Generate a bounded real-transaction split circuit profile.

The parent profile has one empty-script input and one token output at vout 0.
This is deliberately not a general transaction parser or provenance proof.
"""
from hashlib import sha256
from pathlib import Path

from shared.pushtx import PUBLIC
from shared.transaction import Input, Output, Transaction, blob
from transaction_relation import MARKER, TokenState, token_lock


def circuit_source() -> str:
    sentinel = b'profile-only-verifier'
    script = token_lock(TokenState(bytes(32), 1, PUBLIC), sentinel)
    metadata = len(MARKER) + 1
    owner = metadata + 40
    owner_tail = len(script) - 34
    guard = script.index(sha256(blob(sentinel)).digest())
    parent = Transaction((Input(bytes(32), 0),), (Output(1, script),)).serialize()
    parent_script = parent.index(script)
    output = Output(1, script).serialize()
    output_script = output.index(script)
    include = Path(__file__).resolve().parents[1] / 'circuits/transfer_commitment.circom'
    lines = [
        'pragma circom 2.2.3;', f'include "{include}";',
        'template ActualSplit() {',
        'signal input prefix[64]; signal input preimage[192];',
        'signal input inputSlots[1][12]; signal input outputSlots[2][12];',
        'signal input digestHigh; signal input digestLow;',
        f'signal input parent[{len(parent)}]; signal input prevouts[72];',
        f'signal input outputs[{2 * len(output)}];',
        'component statement = TransferCommitment(1, 2, 192);',
        'statement.digestHigh <== digestHigh; statement.digestLow <== digestLow;',
        'for (var i=0; i<64; i++) statement.prefix[i] <== prefix[i];',
        'for (var i=0; i<192; i++) statement.preimage[i] <== preimage[i];',
        'for (var j=0; j<12; j++) statement.inputSlots[0][j] <== inputSlots[0][j];',
        'for (var i=0; i<2; i++) for (var j=0; j<12; j++) statement.outputSlots[i][j] <== outputSlots[i][j];',
        f'component parentHash = Hash256Bytes({len(parent)});',
        f'component outputsHash = Hash256Bytes({2 * len(output)});',
        'component prevoutsHash = Hash256Bytes(72);',
        f'for (var i=0; i<{len(parent)}; i++) parentHash.data[i] <== parent[i];',
        f'for (var i=0; i<{2 * len(output)}; i++) outputsHash.data[i] <== outputs[i];',
        'for (var i=0; i<72; i++) prevoutsHash.data[i] <== prevouts[i];',
        'for (var i=0; i<32; i++) {',
        'parentHash.digest[i] === prevouts[36+i];',
        'prevoutsHash.digest[i] === preimage[4+i];',
        'outputsHash.digest[i] === preimage[152+i]; }',
        'for (var i=0; i<36; i++) prevouts[i] === preimage[68+i];',
        'for (var i=68; i<72; i++) prevouts[i] === 0;',
        'inputSlots[0][0] === 1;',
        'for (var i=1; i<4; i++) inputSlots[0][i] === 0;',
        'for (var i=0; i<2; i++) { outputSlots[i][0] === i;',
        'for (var j=1; j<4; j++) outputSlots[i][j] === 0; }',
    ]
    # Parse the exact parent envelope. Only the previous outpoint, sequence,
    # carrier satoshis and locktime are variable; script length/counts are pinned.
    variable = set(range(5, 41)) | set(range(42, 46)) | set(range(47, 55)) | set(range(len(parent)-4, len(parent)))
    variable |= set(range(parent_script, parent_script + len(script)))
    for i, value in enumerate(parent):
        if i not in variable:
            lines.append(f'parent[{i}] === {value};')
    for output_index in range(2):
        base = output_index * len(output)
        for i in range(8, output_script):
            lines.append(f'outputs[{base+i}] === {output[i]};')
    for label, start, slots in [('parent', parent_script, 'inputSlots[0]'),
                                ('outputs', output_script, 'outputSlots[0]'),
                                ('outputs', len(output)+output_script, 'outputSlots[1]')]:
        for i, value in enumerate(script):
            lhs = f'{label}[{start+i}]'
            if metadata <= i < metadata+32:
                rhs = f'prefix[{i-metadata}]'
            elif metadata+32 <= i < metadata+40:
                rhs = f'{slots}[{4+i-metadata-32}]'
            elif owner <= i < owner+33:
                continue
            elif owner_tail <= i < owner_tail+33:
                rhs = f'{label}[{start+owner+i-owner_tail}]'
            elif guard <= i < guard+32:
                rhs = f'parent[{parent_script+i}]'
            else:
                rhs = str(value)
            if lhs != rhs:
                lines.append(f'{lhs} === {rhs};')
        # Compressed pubkey encoding; input CHECKSIG authenticates the curve point.
        lines.append(f'({label}[{start+owner}]-2)*({label}[{start+owner}]-3) === 0;')
    lines += ['}', 'component main {public [digestHigh, digestLow]} = ActualSplit();']
    return '\n'.join(lines) + '\n'
