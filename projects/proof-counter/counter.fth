( Increment in u32 and choose the successor from the wrapped value. )
: advance ( u32 -- u32 ) 1 cell>u32 u32+ ;

: needs-review ( u32 -- cell ) #20 cell>u32 u32< ;

: decide ( u32 -- route ) needs-review IF route-review ELSE route-settle THEN ;
