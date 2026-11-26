( Prepare with a guard on x. Work a must use that same x. )
: u32-inc ( u32 -- u32 ) 1 cell>u32 u32+ ;

: eligible ( u32 -- cell ) 32 cell>u32 u32< ;

: double ( u32 -- u32 ) dup u32+ ;

: decide ( u32 u32 -- route ) u32+ 20 cell>u32 u32< if route-review else route-settle then ;

gate: prepare x eligible operator ;
work: a x double alice ;
work: b y u32-inc bob ;
join: route a b decide ;
split-authority: operator ;
independent-submit: a ;
independent-submit: b ;
recovery: 180 review ;
