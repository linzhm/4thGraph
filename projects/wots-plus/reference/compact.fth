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

: compact-prf-pair ( script cell -- script )
    ( Build-time argument is the selector bit depth. )
    ( Hash the address with selector zero. Set its last bit and hash for the mask. )
    swap op-dup op-sha256 op-swap swap bsv-num op-pick op-or op-sha256
;

: compact-hash-address ( script cell cell -- script )
    ( Build-time arguments are the selector bit and function prefix depths. )
    rot rot compact-prf-pair
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

: compact-chain-input ( script -- script )
    ( PRF base, endpoints, remaining signature, chain index. )
    op-swap 32 bsv-num op-split op-swap
    op-4 op-pick op-3 op-pick
;

: compact-step-count ( script -- script )
    op-15 op-fromaltstack op-sub
;

: compact-v2-chain-start ( script -- script )
    compact-chain-input op-1 op-num2bin op-cat op-swap compact-step-count
;

: compact-countdown-gate ( script -- script )
    ( A zero counter is consumed. A positive counter enters the next gate. )
    op-ifdup op-if op-1sub
;

: compact-v2-hash-step ( script cell -- script )
    ( Chain address, value. The build-time argument is the step table depth. )
    swap op-over swap bsv-num op-pick op-cat
    9 6 compact-hash-address
;

: compact-append-endpoint ( script -- script )
    op-3 op-roll op-swap op-cat op-swap op-rot
;

: compact-v2-chain-end ( script -- script )
    op-nip compact-append-endpoint op-1add
;

: compact-chain-prefix ( script -- script )
    ( The index is a raw byte, including the initial zero. )
    compact-chain-input op-cat
    ( Keep the zero function prefix immediately below the chain address. )
    op-6 op-pick op-swap op-rot
;

: compact-v3-chain-start ( script -- script )
    compact-chain-prefix compact-step-count
;

: compact-v3-hash-step ( script cell -- script )
    ( Zero function prefix, chain address, value. )
    ( Copy the prefix and address together, then append the step suffix. )
    bsv-num op-pick op-2over op-rot op-cat
    11 compact-prf-pair
    ( The copied prefix is already below the key and masked value. )
    op-3 op-roll op-xor op-cat op-cat op-sha256
;

: compact-v3-chain-end ( script -- script )
    op-rot op-drop op-nip compact-append-endpoint op-bin2num op-1add
;

: compact-v4-chain-start ( script -- script )
    ( Also keep the selector bit mask next to the chain value. )
    compact-chain-prefix op-8 op-pick op-swap compact-step-count
;

: compact-local-hash-pair ( script -- script )
    op-pick op-cat
    ( Keep the address below the copied prefix and key, then move it next to the value. )
    op-tuck op-sha256 op-2swap op-4 op-pick op-or op-sha256
    ( The copied prefix and key are already below the value and mask. )
    op-xor op-cat op-cat op-sha256
;

: compact-local-hash-step ( script cell -- script )
    ( Function prefix, chain address, selector mask, value. )
    swap op-2over swap bsv-num compact-local-hash-pair
;

: compact-v4-chain-end ( script -- script )
    op-2swap op-2drop op-nip compact-append-endpoint op-bin2num op-1add
;

: compact-v5-chain-start ( script -- script )
    ( PRF base, function prefix, selector mask, remaining signature, index, endpoints. )
    op-2swap 32 bsv-num op-split op-2rot op-tuck
    op-7 op-pick op-swap op-cat op-2rot
    ( Endpoints, remaining signature and index sit below the four hash operands. )
    op-fromaltstack
;

: compact-v5-chain-end ( script -- script )
    ( Restore the frame while incrementing the index and appending the endpoint. )
    op-swap op-2rot op-bin2num op-1add op-6 op-roll op-2rot op-nip op-cat
;

: compact-v6-chain-start ( script -- script )
    ( The altstack holds the signature and endpoints buffer above the step counts. )
    op-fromaltstack 32 bsv-num op-split op-fromaltstack op-swap op-toaltstack
;

: compact-buffer-append ( script -- script )
    ( Append the endpoint behind the remaining signature and previous endpoints. )
    op-fromaltstack op-swap op-cat op-toaltstack
;

: compact-address-increment ( script -- script )
    ( Increment the final byte of the PRF base while preserving the other bytes. )
    op-3 op-pick op-add op-swap
;

: compact-v6-chain-end ( script -- script )
    compact-buffer-append op-swap op-bin2num compact-address-increment
;

: compact-v7-chain-end ( script -- script )
    ( The first chain inserts BIN2NUM before the increment. )
    compact-buffer-append op-swap compact-address-increment
;

: compact-v8-chain-start ( script -- script )
    ( The buffer is on the main stack between chains. Park its tail while hashing. )
    32 bsv-num op-split op-fromaltstack op-swap op-toaltstack
;

: compact-v8-chain-tail ( script -- script )
    ( The delta sits below twelve step suffixes, selector, endpoint, prefix and address. )
    op-16 op-pick op-add op-2swap
    op-fromaltstack op-swap op-cat
;

: compact-v8-chain-end ( script -- script )
    ( Move the address to the top. The first chain inserts BIN2NUM here. )
    op-2swap compact-v8-chain-tail
;
