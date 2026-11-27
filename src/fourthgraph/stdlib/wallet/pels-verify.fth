REQUIRE pels-successor.fth
REQUIRE pels-binding.fth

( The witness supplies the BIP143 fields on either side of hashOutputs. )
( Construct the omitted output commitment, then authenticate the message. )
( This profile fixes BIP143 ALL, a single input and a single successor. )

: pels-check-message-tail ( script -- script )
    ( Runtime: tail head state -- tail head state. )
    op-2 op-pick op-size op-8 op-numequalverify
    op-4 op-split op-nip bytes-hex 41000000 bsv-push op-equalverify
;

: pels-candidate-context ( script -- script )
    ( Runtime: tail head state -- tail state previous-amount | alt: head scriptCode. )
    pels-check-message-tail op-swap
    pels-assert-one-input op-dup op-toaltstack
    op-size 12 bsv-num op-sub op-split
    op-8 op-split op-drop op-swap pels-read-script-code
    op-toaltstack op-bin2num
;

: pels-assemble-message ( script -- script )
    ( Runtime: tail hashOutputs | alt: head -- full candidate message. )
    op-fromaltstack op-swap op-cat op-swap op-cat
;

: pels-verify ( script script -- script )
    ( Build arguments: prefix and a state/amount rule. )
    ( Runtime: tail head state -- authenticated digest. )
    swap pels-candidate-context swap bsv-cat-code
    pels-successor-hash pels-assemble-message op-hash256 pels-bind-digest
;
