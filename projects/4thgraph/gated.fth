( All u32 additions wrap modulo 2^32. A wrapped sum below 20 goes to review. )
: double ( u32 -- u32 ) DUP u32+ ;

: inc ( u32 -- u32 ) u32>cell 1 + cell>u32 ;

: decide ( u32 u32 -- route ) u32+ 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;

work: a x double alice ;
work: b y inc bob ;
join: route a b decide ;
split-authority: operator ;

( The admission check must succeed before the two work outputs can exist. )
: eligible ( u32 -- cell ) 5 cell>u32 u32< ;
gate: qualify z eligible operator ;
