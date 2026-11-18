# The four-byte LE type is fixed by the transaction digest. Ignore only the
# Chronicle OTDA and ANYONECANPAY bits, then require base ForkID ALL/NONE/SINGLE.
block CHECK_TYPE
  0x5fffffff OP_AND @LE_UNSIGNED 65 68 OP_WITHIN OP_VERIFY
end
