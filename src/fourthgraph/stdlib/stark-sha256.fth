REQUIRE BSV

( Compile-time words for the fixed-shape STARK verifier. )
: stark-packet-entry ( script cell -- script )
    swap op-depth op-1 op-numequalverify op-size swap bsv-num op-numequalverify
;

: stark-le-unsigned ( script -- script )
    bytes-hex 00 bsv-push op-cat op-bin2num
;

: stark-unsigned-le ( script cell -- script )
    dup 1 + rot swap bsv-num op-num2bin swap bsv-num op-split op-drop
;

( The runtime input is the canonical row, the digest pair or the transcript bytes. )
: stark-leaf-hash ( script -- script )
    bytes-hex 00 bsv-push op-swap op-cat op-sha256
;
: stark-node-hash ( script -- script )
    bytes-hex 01 bsv-push op-swap op-cat op-sha256
;
: stark-transcript-hash ( script -- script )
    bytes-hex 02 bsv-push op-swap op-cat op-sha256
;

( Runtime stack contains the current value, its sibling and the bit selecting the right child. )
: stark-order-pair ( script -- script )
    op-if op-swap op-endif op-cat
;
