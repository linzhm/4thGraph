REQUIRE BSV

: compact-chain-start ( script -- script )
    ( PRF base, checksum, endpoints, remaining signature, chain index. )
    op-swap 32 bsv-num op-split op-swap
    op-5 op-pick op-3 op-pick op-1 op-num2bin op-cat
    op-fromaltstack op-rot
;

: compact-if-digit-below ( script cell -- script )
    swap op-over swap bsv-num op-lessthan op-if
;

: compact-hash-address ( script cell cell -- script )
    ( Build-time arguments are the selector bit and function prefix depths. )
    ( Hash the address with selector zero. Set its last bit and hash for the mask. )
    rot op-dup op-sha256 op-swap rot bsv-num op-pick op-or op-sha256
    op-rot op-xor op-cat
    ( Hash the zero function prefix, key and masked value. )
    swap bsv-num op-pick op-swap op-cat op-sha256
;

: compact-hash-step ( script cell -- script )
    ( Chain address, digit, value. The build-time argument is the step table depth. )
    swap op-2 op-pick swap bsv-num op-pick op-cat
    11 8 compact-hash-address
;

: compact-chain-end ( script -- script )
    ( Append the endpoint, then advance the index for the next chain. )
    op-rot op-drop op-nip op-3 op-roll op-swap op-cat op-swap op-rot op-1add
;

: compact-v2-chain-start ( script -- script )
    ( PRF base, endpoints, remaining signature, chain index. )
    op-swap 32 bsv-num op-split op-swap
    op-4 op-pick op-3 op-pick op-1 op-num2bin op-cat
    op-swap op-15 op-fromaltstack op-sub
;

: compact-v2-countdown-gate ( script -- script )
    ( A zero counter is consumed. A positive counter enters the next gate. )
    op-ifdup op-if op-1sub
;

: compact-v2-hash-step ( script cell -- script )
    ( Chain address, value. The build-time argument is the step table depth. )
    swap op-over swap bsv-num op-pick op-cat
    9 6 compact-hash-address
;

: compact-v2-chain-end ( script -- script )
    op-nip op-3 op-roll op-swap op-cat op-swap op-rot op-1add
;
