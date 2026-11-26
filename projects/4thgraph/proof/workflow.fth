( Increment in u32 and choose the successor from the wrapped value. )
: advance ( u32 -- u32 ) 1 cell>u32 u32+ ;

: decide ( u32 -- route ) 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;

workflow-input: current u32 ;
stage: advance advance current next operator ;
stage: decide decide next route bob ;
