( Increment in u32 and choose the successor from the wrapped value. )
bsv-effect: advance u32 -- u32 ;
: advance 1 cell>u32 u32+ ;

bsv-effect: decide u32 -- route ;
: decide 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;
