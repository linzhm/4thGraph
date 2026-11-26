( Two u32 transitions followed by a route decision. )
: u32-inc ( u32 -- u32 ) 1 cell>u32 u32+ ;

: double ( u32 -- u32 ) dup u32+ ;

: decide ( u32 -- route ) 20 cell>u32 u32< if route-review else route-settle then ;

workflow-input: current u32 ;
stage: increment u32-inc current next operator ;
stage: scale double next scaled alice ;
stage: decide decide scaled route bob ;
