REQUIRE stdlib/byte-layout.fth

: sm2-reverse-fields-kernel ( script -- script )
    6 reverse-32-fields ;

: sm2-zero32-kernel ( script -- script )
    bytes-hex 0000000000000000000000000000000000000000000000000000000000000000 byte-constant ;
