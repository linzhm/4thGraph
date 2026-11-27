REQUIRE BSV

: lamport-read-digest-byte ( script -- script )
    op-1 op-split op-swap bytes-hex 00 bsv-push op-cat op-bin2num
;

: lamport-full-verifier ( script bytes -- script )
    swap
    256 0 DO
        i lamport-bit-index 0 = IF lamport-read-digest-byte op-swap op-toaltstack THEN
        op-dup op-2 op-mod op-if
        over i lamport-key-one bsv-push op-else
        over i lamport-key-zero bsv-push op-endif
        op-toaltstack op-2 op-div op-swap
        32 bsv-num op-split op-swap op-sha256 op-fromaltstack op-equalverify op-swap
        i lamport-bit-index 7 = IF op-drop op-fromaltstack THEN
    LOOP
    op-0 op-equalverify op-0 op-equalverify nip
;

: lamport-committed-byte ( script -- script )
    lamport-read-digest-byte op-swap op-toaltstack op-0 op-rot
    8 0 DO
        32 bsv-num op-split op-swap op-sha256 op-swap
        32 bsv-num op-split op-toaltstack
        op-3 op-pick op-2 op-mod op-if op-swap op-endif op-cat op-cat
        op-swap op-2 op-div op-swap op-fromaltstack
    LOOP
    op-rot op-0 op-equalverify op-fromaltstack op-fromaltstack
    op-3 op-roll op-cat op-toaltstack
;

: lamport-committed-verifier ( script bytes -- script )
    swap op-0 op-toaltstack
    32 0 DO lamport-committed-byte LOOP
    op-0 op-equalverify op-0 op-equalverify op-fromaltstack op-sha256
    swap bsv-push op-equalverify
;

: lamport-legacy-binding ( script -- script )
    lamport-binding-der bytes-hex 41 bsv-push op-cat
    lamport-binding-key bsv-push op-codeseparator op-checksig
;

: lamport-two-item-guard ( script cell -- script )
    swap op-depth op-2 op-numequalverify op-over op-size
    swap bsv-num op-numequalverify op-drop op-size
    8192 bsv-num op-numequalverify
;

: lamport-legacy-lock ( script bytes -- script )
    swap 158 lamport-two-item-guard
    op-over 104 bsv-num op-split op-nip op-2 op-split op-drop
    bytes-hex 01ac bsv-push op-equalverify
    op-over 154 bsv-num op-split op-nip bytes-hex 41000000 bsv-push op-equalverify
    op-swap op-hash256 op-dup op-toaltstack
    swap lamport-full-verifier op-fromaltstack lamport-legacy-binding
;

: lamport-detached-lock ( script bytes -- script )
    swap 32 lamport-two-item-guard op-swap swap lamport-full-verifier op-1
;

: lamport-payment-guard ( script cell cell -- script )
    rot swap lamport-authorize op-size swap bsv-num op-numequalverify
    op-swap op-hash256 op-dup op-toaltstack
;

: lamport-payment-binding ( script cell -- script )
    swap op-fromaltstack swap lamport-bind
;

: lamport-payment-lock ( script script cell -- script )
    rot swap 0 lamport-payment-guard swap bsv-cat-code
    0 lamport-payment-binding
;
