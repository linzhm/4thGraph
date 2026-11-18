# Validate the complete four-byte little-endian sighash type.
block CHECK_TYPE
  0x5fffffff OP_AND @LE_UNSIGNED 65 68 OP_WITHIN OP_VERIFY
end
