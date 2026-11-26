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

: compact-hash-step ( script cell -- script )
    ( Chain address, digit, value. The build-time argument is the step table depth. )
    swap op-2 op-pick swap bsv-num op-pick op-cat
    ( Hash the address with selector zero. Set its last bit and hash for the mask. )
    op-dup op-sha256 op-swap op-11 op-pick op-or op-sha256
    op-rot op-xor op-cat
    ( Hash the zero function prefix, key and masked value. )
    op-8 op-pick op-swap op-cat op-sha256
;

: compact-chain-end ( script -- script )
    ( Append the endpoint, then advance the index for the next chain. )
    op-rot op-drop op-nip op-3 op-roll op-swap op-cat op-swap op-rot op-1add
;
