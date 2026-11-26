( Advance by three, then route the wrapped counter at the threshold twelve. )
: add-three ( u32 -- u32 ) 3 cell>u32 u32+ ;

: choose-destination ( u32 -- route ) 12 cell>u32 u32< IF route-review ELSE route-settle THEN ;

workflow-input: counter u32 ;
stage: notify choose-destination advanced outcome bob ;
stage: update add-three counter advanced operator ;
