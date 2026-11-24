# Research-only replacement for UINT256BE + K1_BIND_DIGEST. Input is a raw
# 32-byte big-endian digest. The sighash byte is on top of the alt stack.
# For each delta, Q = (delta * 2^248 / r mod n) G on secp256k1, r = x(G).
# All three keys are public PUSHTX parameters. They confer no spending authority.
bytes PLUS_1 02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0
bytes MINUS_125 025e2712323ef579d335d8b92e43f6df2d5493d253f16ddd7f385a2db27aee831c
bytes MINUS_251 03687d983b7b373ce10f50c7fb2ed2aa0fc4b5c028c21567fbadb1008dbc381fea
bytes DER_PREFIX 3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980220

block BIND_RAW_DIGEST
  OP_1 OP_SPLIT OP_SWAP 0x00 OP_CAT OP_BIN2NUM
  OP_DUP 126 OP_LESSTHAN OP_IF
    OP_1ADD @PLUS_1
  OP_ELSE
    OP_DUP 252 OP_LESSTHAN OP_IF
      125 OP_SUB @MINUS_125
    OP_ELSE
      251 OP_SUB @MINUS_251
    OP_ENDIF
  OP_ENDIF
  # The adjusted high byte is in [1,126]. The remaining 31 bytes stay intact.
  OP_TOALTSTACK OP_1 OP_NUM2BIN OP_SWAP OP_CAT @DER_PREFIX OP_SWAP OP_CAT
  OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT OP_SWAP OP_CAT OP_SWAP
end
