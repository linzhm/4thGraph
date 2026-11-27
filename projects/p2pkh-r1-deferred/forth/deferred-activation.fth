\ Published metadata is compiled separately so it stays readable at fixed offsets.
: deferred-metadata ( -- )
    funding-owner target-script-hash 2drop ;

: bytes-skip ( bytes cell -- bytes )
    bytes-split nip ;

\ Reverse exactly 32 bytes with a balanced split tree and no altstack traffic.
: reverse-2 ( bytes -- bytes )
    1 bytes-split swap bytes-cat ;
: reverse-4 ( bytes -- bytes )
    2 bytes-split reverse-2 swap reverse-2 bytes-cat ;
: reverse-8 ( bytes -- bytes )
    4 bytes-split reverse-4 swap reverse-4 bytes-cat ;
: reverse-16 ( bytes -- bytes )
    8 bytes-split reverse-8 swap reverse-8 bytes-cat ;
: reverse-32 ( bytes -- bytes )
    16 bytes-split reverse-16 swap reverse-16 bytes-cat ;

: le-unsigned ( bytes -- script-int )
    bytes-hex 00 bytes-cat bytes>int ;

\ The fixed transaction-binding key and nonce are both the public scalar 1.
\ These two constants are little-endian, positive ScriptNums.
: k1-generator-x ( -- script-int )
    bytes-hex 9817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79 bytes>int ;
: k1-order ( -- script-int )
    bytes-hex 414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00 bytes>int ;

: low-s ( script-int -- script-int )
    k1-generator-x int+ k1-order tuck int-rem
    dup int-verify tuck int- int-min ;

: s>der-bytes ( script-int -- bytes )
    dup int>bytes bytes-length
    swap 32 int>bin reverse-32
    swap 32 swap - bytes-skip ;

: prefix-length ( bytes -- bytes )
    dup bytes-length cell>int int>bytes swap bytes-cat ;

: digest>signature ( bytes bytes -- bytes )
    ( digest sighash-byte -- DER-with-sighash )
    swap reverse-32 le-unsigned low-s s>der-bytes prefix-length
    bytes-hex 022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802
    swap bytes-cat prefix-length bytes-hex 30 swap bytes-cat
    swap bytes-cat ;

: direct-preimage ( bytes -- bytes bytes )
    158 bytes-check-size dup 104 bytes-skip 2 bytes-split swap
    bytes-hex 01ac bytes-verify= ;

: companion-preimage ( bytes -- bytes bytes )
    161 bytes-check-size dup 104 bytes-skip 5 bytes-split swap
    bytes-hex 04ad68abac bytes-verify= ;

: bip143-single? ( bytes -- cell )
    bytes-hex 7f bytes-and bytes-hex 43 bytes= ;

: check-output-and-type ( bytes -- bytes )
    8 bytes-split swap input-value bytes-verify=
    4 bytes-skip 32 bytes-split swap
    dup 0 cell>int 32 int>bin bytes= 0= verify
    target-txout-hash bytes-verify=
    4 bytes-skip 1 bytes-split bytes-hex 000000 bytes-verify=
    dup bip143-single? verify ;

: bound-digest ( bytes cell -- bytes bytes )
    ( preimage companion? -- digest sighash-byte )
    if companion-preimage else direct-preimage then
    check-output-and-type swap bytes-hash256 swap ;

: anyonecanpay-bit ( bytes -- bytes )
    bytes-hex 80 bytes-and ;

: check-selected-type ( bytes -- bytes )
    dup bytes-hex 5f bytes-and bytes>int 65 68 int-within? verify
    dup bip143-single? 0= verify ;

: selected-signature ( bytes bytes bytes -- bytes )
    ( bound-type bound-signature auxiliary -- selected-signature )
    33 bytes-check-size 1 bytes-split
    2swap bytes>alt
    anyonecanpay-bit rot dup anyonecanpay-bit rot bytes-verify=
    check-selected-type digest>signature ;

: deferred-activation ( bytes -- cell )
    ( [auxiliary] preimage -- success )
    witness-depth dup 1 3 cell-within? verify 2 =
    dup flag>alt bound-digest tuck digest>signature
    alt>flag if
        reveal-auxiliary selected-signature 1
    else
        nip 0
    then
    swap bytes-hex 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 rot
    check-activation-signatures ;
