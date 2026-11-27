REQUIRE stdlib/pels.fth
bytes-param: recipient-lock 1 ;

( This fixture binds OP_1 as the recipient lock. )
: payout ( -- output ) 10000 recipient-lock tx-output ;
: receipt ( -- output ) 0 bytes-hex 006a055245414459 tx-output ;

lock: settle ( )
    1 inputs= verify
    payout receipt 2 outputs= verify
    tx-locktime 42 = verify
;
