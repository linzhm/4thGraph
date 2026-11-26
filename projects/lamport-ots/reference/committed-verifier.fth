REQUIRE BSV

\ Split one 64-byte proof record into a selected secret and the sibling hash.
\ Main stack after the split: digest-byte chunk selected-hash sibling-hash.
\ The rest of the proof waits on altstack while the pair is ordered.
: split-pair ( bytes bytes bytes -- bytes bytes bytes bytes )
  32 OP_SPLIT SWAP OP_SHA256 SWAP 32 OP_SPLIT save-bytes ;

\ Compare bytes, so the high-bit mask 80 never becomes ScriptNum negative zero.
: append-pair ( bytes bytes bytes bytes bytes bytes -- bytes bytes bytes )
  TUCK bytes-and OP_EQUAL swap-if OP_CAT OP_CAT restore-bytes ;

\ Entry and exit: accumulated-key remaining-proof remaining-digest.
: committed-byte ( bytes bytes bytes -- bytes bytes bytes )
  1 OP_SPLIT save-bytes empty-bytes ROT
  split-pair copy-digest-byte bytes-hex 01 append-pair
  split-pair copy-digest-byte bytes-hex 02 append-pair
  split-pair copy-digest-byte bytes-hex 04 append-pair
  split-pair copy-digest-byte bytes-hex 08 append-pair
  split-pair copy-digest-byte bytes-hex 10 append-pair
  split-pair copy-digest-byte bytes-hex 20 append-pair
  split-pair copy-digest-byte bytes-hex 40 append-pair
  split-pair copy-digest-byte bytes-hex 80 append-pair
  ROT DROP save-bytes OP_CAT restore-bytes restore-bytes ;

\ The payment lock has already checked the proof length and computed SHA256d(P).
\ Consume both strings and leave SHA256 of the reconstructed ordered key.
: start-commitment ( bytes bytes -- bytes bytes bytes ) empty-bytes ROT ROT ;
: finish-commitment ( bytes bytes bytes -- bytes )
  empty-bytes OP_EQUALVERIFY empty-bytes OP_EQUALVERIFY OP_SHA256 ;
