REQUIRE BSV

: sha256-tagged ( bytes bytes -- bytes )
    swap bytes-cat bytes-sha256 ;

: stark-sha256-bytes ( bytes -- bytes )
    bytes-hex 00 sha256-tagged ;

: stark-sha256-trace-row ( bytes -- bytes )
    #32 bytes-check-size bytes-hex 01 sha256-tagged ;

: stark-sha256-merkle-parent ( bytes bytes -- bytes )
    #32 bytes-check-size swap #32 bytes-check-size swap
    bytes-cat bytes-hex 02 sha256-tagged ;

( The caller supplies an already parsed vector of digests in order. )
: stark-sha256-digest-list ( bytes -- bytes )
    bytes-hex 03 sha256-tagged ;

: stark-sha256-seed-counter ( bytes bytes -- bytes )
    #8 bytes-check-size swap #32 bytes-check-size swap
    bytes-cat bytes-hex 04 sha256-tagged ;
