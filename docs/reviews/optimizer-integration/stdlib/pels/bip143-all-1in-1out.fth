REQUIRE pels-verify.fth

( Review-only interface over the #83 assembly words. )
: pels-verify-preimage ( script script -- script )
    ( Runtime: tail head state -- authenticated-preimage. )
    swap pels-candidate-context swap bsv-cat-code
    pels-successor-hash pels-assemble-message
    op-dup op-hash256 pels-bind-digest op-drop
;

: pels-assert-locktime ( script bytes -- script )
    ( Build: expected nLockTime in four wire-order bytes. )
    ( Runtime: authenticated-preimage -- same authenticated-preimage. )
    4 bytes-check-size swap
    op-dup op-size op-8 op-sub op-split op-nip op-4 op-split op-drop
    swap bsv-push op-equalverify
;
