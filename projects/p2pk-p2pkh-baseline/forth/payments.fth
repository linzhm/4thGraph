( Construct the native locking scripts at build time. )
bsv-effect: p2pk bytes -- bytes ;
: p2pk
  bytes-hex 21 swap bytes-cat          ( push a 33-byte public key )
  bytes-hex ac bytes-cat ;             ( OP_CHECKSIG )

bsv-effect: p2pkh bytes -- bytes ;
: p2pkh
  bytes-hex 76a914 swap bytes-cat      ( OP_DUP OP_HASH160 push20 )
  bytes-hex 88ac bytes-cat ;           ( OP_EQUALVERIFY OP_CHECKSIG )
