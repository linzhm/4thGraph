REQUIRE BSV

REQUIRE counter.fth

workflow-input: current u32 ;
stage: advance advance current next operator ;
stage: decide decide next route bob ;
