REQUIRE hashes.fth

: stark-sha256-trace-root ( bytes bytes u32 -- bytes )
    rot stark-sha256-trace-row rot rot
    merkle-sha256-root #13 02 ;

bytes-param: trace-root 32 ;

lock: verify-trace-opening ( row:bytes path:bytes index:u32 )
    row path index stark-sha256-trace-root trace-root OP_EQUAL verify ;
