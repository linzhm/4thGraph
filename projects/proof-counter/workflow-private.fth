REQUIRE BSV
REQUIRE counter.fth

range: private-delta u32 1 5 ;

: decide-with-delta ( u32 u32 -- route )
    check-range private-delta u32+ decide ;

workflow-input: current u32 ;
stage: advance advance current next operator ;
stage: decide decide-with-delta next route bob ;
private-witness: decide delta u32 ;
policy: decide require-zk ;
atomic: advance decide ;
