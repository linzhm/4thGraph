REQUIRE BSV

: wots-canonical-digits ( script -- script )
    op-0
    32 0 DO
        op-swap 31 i - bsv-num op-split bytes-hex 00 bsv-push op-cat op-bin2num
        op-dup op-16 op-mod op-dup op-toaltstack
        op-swap op-16 op-div op-dup op-toaltstack op-add op-rot op-add
    LOOP
    op-nip 960 bsv-num op-swap op-sub
;

: wots-step-address ( script cell -- script )
    wots-step-cache? IF
        25 swap - bsv-num op-pick
    ELSE
        wots-u32be bsv-push
    THEN
;

: wots-canonical-chain ( script cell -- script )
    swap 32 bsv-num op-split op-swap op-4 op-pick
    swap wots-u32be bsv-push op-cat op-swap op-fromaltstack
    15 0 DO
        op-dup i bsv-num op-greaterthan op-notif op-swap
        op-2 op-pick i wots-step-address op-cat op-dup
        wots-cache? IF op-10 op-pick ELSE op-0 op-4 op-num2bin THEN
        op-cat op-sha256 op-swap
        wots-cache? IF op-9 op-pick ELSE bytes-hex 00000001 bsv-push THEN
        op-cat op-sha256 op-rot op-xor op-cat
        wots-cache? IF op-9 op-pick ELSE op-0 32 bsv-num op-num2bin THEN
        op-swap op-cat op-sha256 op-swap op-endif
    LOOP
    op-drop op-nip op-rot op-swap op-cat op-swap
;

: wots-canonical-constants ( script -- script )
    wots-cache? IF
        wots-step-cache? IF 15 0 DO i wots-u32be bsv-push LOOP THEN
        32 wots-zero-bytes bsv-push 4 wots-zero-bytes bsv-push bytes-hex 00000001 bsv-push
    THEN
;

: wots-canonical-roll ( script -- script )
    wots-step-cache? IF 20 ELSE 5 THEN bsv-num op-roll
;

: wots-canonical-prf-prefix ( bytes -- bytes )
    bytes-hex 0000000000000000000000000000000000000000000000000000000000000003
    swap bytes-cat 20 wots-zero-bytes bytes-cat
;

: wots-canonical-verify ( script bytes bytes -- script )
    rot wots-canonical-constants
    rot wots-canonical-prf-prefix bsv-push
    wots-cache? IF wots-canonical-roll wots-canonical-roll ELSE op-rot op-rot THEN
    wots-canonical-digits op-swap op-0 op-swap
    64 0 DO i wots-canonical-chain LOOP
    op-2 op-pick op-dup op-16 op-mod op-toaltstack op-16 op-div
    op-dup op-16 op-mod op-toaltstack op-16 op-div op-toaltstack
    67 64 DO i wots-canonical-chain LOOP
    op-0 op-equalverify op-sha256 swap bsv-push op-equalverify op-2drop
    wots-cache? IF
        op-2drop op-drop
        wots-step-cache? IF 7 0 DO op-2drop LOOP op-drop THEN
    THEN
;

: wots-canonical-lock ( script bytes bytes -- script )
    rot wots-authorize op-size 2144 bsv-num op-numequalverify
    op-swap op-hash256 op-dup op-toaltstack
    rot rot wots-canonical-verify op-fromaltstack wots-bind
;

: wots-canonical-detached ( script bytes bytes -- script )
    rot op-depth op-2 op-numequalverify op-over op-size 32 bsv-num
    op-numequalverify op-drop op-size 2144 bsv-num op-numequalverify op-swap
    rot rot wots-canonical-verify op-1
;
