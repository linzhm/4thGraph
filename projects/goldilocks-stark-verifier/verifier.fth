REQUIRE stdlib/stark-sha256.fth

: verify-proof ( script cell script -- script )
    rot rot stark-packet-entry swap bsv-cat-code op-1
;
