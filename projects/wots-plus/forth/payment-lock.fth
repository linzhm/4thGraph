REQUIRE compact.fth

( WOTS+ v0.12.0 uses the compact-v11 layout. The compiler supplies
  the two shared transaction-binding words. The seed and commitment are
  build-time arguments. )

: wots-v11-zeroes ( script cell -- script )
    swap op-0 swap bsv-num op-num2bin
;

: wots-v11-padded-one ( script cell -- script )
    wots-v11-zeroes op-1 op-cat
;

: wots-v11-digest-checksum ( script -- script )
    op-invert op-dup op-15
    5 0 DO op-dup op-cat LOOP
    op-2dup op-and op-bin2num op-rot op-4 op-rshift op-rot op-and op-bin2num op-add
    op-dup 256 bsv-num op-div op-add 32 bsv-num op-num2bin
    bytes-hex ff00 bsv-push
    4 0 DO op-dup op-cat LOOP
    op-and op-bin2num 65535 bsv-num op-mod op-swap op-toaltstack
;

: wots-v11-split-step ( script -- script ) op-8 op-split ;

: wots-v11-step-table ( script -- script )
    ( For q = 2^64, divide 2^24 times q^15 by the square of q minus one.
      The quotient packs steps 14 through 1. NUM2BIN adds the zero lane. )
    123 wots-v11-padded-one 8 wots-v11-padded-one
    op-1sub op-dup op-mul op-div 120 bsv-num op-num2bin
    3 0 DO wots-v11-split-step LOOP
    87 wots-v11-padded-one op-swap
    11 0 DO wots-v11-split-step LOOP
;

: wots-v11-chain-gates ( script -- script )
    14 0 DO compact-countdown-gate LOOP
    op-if
    15 0 DO
        i 6 + 11 i < IF 1+ THEN compact-local-hash-step op-endif
    LOOP
;

: wots-v11-chain ( script -- script )
    compact-v8-chain-start wots-v11-chain-gates compact-v8-chain-end
;

: wots-v11-high-chain ( script -- script )
    compact-buffer-read
    op-1 op-split op-toaltstack
    op-dup op-15 op-and op-toaltstack op-4 op-rshift
    op-swap op-toaltstack wots-v11-chain-gates op-2swap
;

: wots-v11-message-chains ( script -- script )
    wots-v11-high-chain op-bin2num compact-v8-chain-tail wots-v11-chain
    31 0 DO wots-v11-high-chain compact-v8-chain-tail wots-v11-chain LOOP
;

: wots-v11-checksum-chains ( script -- script )
    op-fromaltstack op-drop 20 bsv-num op-pick 4095 bsv-num op-swap op-sub
    op-dup op-16 op-mod op-toaltstack op-16 op-div
    op-dup op-16 op-mod op-toaltstack op-16 op-div op-toaltstack
    3 0 DO wots-v11-chain LOOP
;

: wots-v11-verify ( script bytes bytes -- script )
    rot wots-v11-digest-checksum wots-v11-step-table
    32 wots-v11-zeroes 31 wots-v11-zeroes op-3 op-cat
    rot bsv-push op-cat 24 wots-v11-zeroes op-cat
    95 wots-v11-padded-one 20 bsv-num op-roll
    wots-v11-message-chains wots-v11-checksum-chains
    op-size 2144 bsv-num op-numequalverify op-sha256
    swap bsv-push op-equalverify
    10 0 DO op-2drop LOOP
;

: wots-v11-lock ( script bytes bytes -- script )
    rot wots-v11-authorize
    op-size 2144 bsv-num op-numequalverify
    op-swap op-hash256 op-dup op-toaltstack
    rot rot wots-v11-verify
    op-fromaltstack wots-v11-bind
;
