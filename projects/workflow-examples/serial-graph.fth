REQUIRE BSV

( Two u32 transitions followed by a route decision. )
REQUIRE stdlib/u32.fth

: double ( u32 -- u32 ) dup u32+ ;

: needs-review ( u32 -- cell ) 20 cell>u32 u32< ;

: decide ( u32 -- route ) needs-review if route-review else route-settle then ;

workflow-input: current u32 ;
stage: increment u32-inc current next operator ;
stage: scale double next scaled alice ;
stage: decide decide scaled route bob ;
