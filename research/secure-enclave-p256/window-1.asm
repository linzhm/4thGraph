# Original one-bit joint window. Preserves the v2 serialized script.
block WINDOW
  OP_0 OP_1 OP_0 @GX @GY OP_1 OP_FROMALTSTACK OP_FROMALTSTACK OP_1
  5 OP_PICK 5 OP_PICK 5 OP_PICK 5 OP_PICK 5 OP_PICK 5 OP_PICK @ADD_POINTS
  # p 3b r O G Q (G+Q), then build a fixed 256-entry digit stack, MSB on top.
  OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP
  repeat 256 DIGIT
  OP_2DROP OP_0 OP_1 OP_0
  repeat 256 SCALAR_STEP
end
block COPY_R_LOW
  16 OP_PICK
end
block COPY_R_HIGH
  15 OP_PICK
end
block CLEAR_POINTS
  repeat 9 DROP_TWO
end
