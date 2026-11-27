REQUIRE BSV

\ Start with the proof and digest. Keep the mask table below the accumulator.
: start-subset ( bytes bytes -- bytes bytes bytes bytes )
  subset-mask-table ROT ROT empty-bytes ROT ROT ;

\ Entry: mask chunk proof. The proof suffix waits on altstack.
: subset-slot ( bytes bytes bytes -- bytes bytes bytes bytes )
  32 OP_SPLIT save-bytes copy-third ;

\ Hash the slot when the mask selects a secret. Append hashes in slot order.
: subset-append ( bytes bytes bytes bytes bytes -- bytes bytes bytes )
  TUCK bytes-and OP_EQUAL hash-if OP_CAT restore-bytes ;

\ Entry and exit: table accumulated-key remaining-proof remaining-digest.
: subset-byte ( bytes bytes bytes bytes -- bytes bytes bytes bytes )
  1 OP_SPLIT save-bytes digest-offset
  copy-fourth SWAP OP_SPLIT NIP 2 OP_SPLIT DROP empty-bytes ROT
  subset-slot bytes-hex 0100 subset-append
  subset-slot bytes-hex 0200 subset-append
  subset-slot bytes-hex 0400 subset-append
  subset-slot bytes-hex 0800 subset-append
  subset-slot bytes-hex 1000 subset-append
  subset-slot bytes-hex 2000 subset-append
  subset-slot bytes-hex 4000 subset-append
  subset-slot bytes-hex 8000 subset-append
  subset-slot bytes-hex 0001 subset-append
  subset-slot bytes-hex 0002 subset-append
  subset-slot bytes-hex 0004 subset-append
  ROT DROP save-bytes OP_CAT restore-bytes restore-bytes ;

: finish-subset ( bytes bytes bytes bytes -- bytes )
  empty-bytes OP_EQUALVERIFY empty-bytes OP_EQUALVERIFY NIP OP_SHA256 ;
