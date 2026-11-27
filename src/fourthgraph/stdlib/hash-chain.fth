REQUIRE BSV
REQUIRE stdlib/script-fragments.fth

( Each application consumes one byte string and leaves one digest. )
: sha256-chain-single ( script cell -- script )
    bsv-empty op-sha256 swap script-append-repeated
;

( Each OP_HASH256 applies SHA-256 twice. The caller emits any odd tail. )
: sha256-chain-pairs ( script cell -- script )
    bsv-empty op-hash256 swap script-append-repeated
;
