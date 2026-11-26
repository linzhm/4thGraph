( All u32 additions wrap modulo 2^32. A wrapped sum below 20 goes to review. )
bsv-effect: double u32 -- u32 ;
: double DUP u32+ ;

bsv-effect: inc u32 -- u32 ;
: inc u32>cell 1 + cell>u32 ;

bsv-effect: decide u32 u32 -- route ;
: decide u32+ 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;

work: a x double alice
work: b y inc bob
join: route a b decide
split-authority: operator
