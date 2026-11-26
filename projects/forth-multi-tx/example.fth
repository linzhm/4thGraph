\ All additions wrap modulo 2^32. A wrapped sum below 20 goes to review.
: double  ( u32 -- u32 ) dup u32+ ;
: inc     ( u32 -- u32 ) 1 u32+ ;
: decide  ( u32 u32 -- route ) u32+ 20 u32< if review else settle then ;

x double alice work: a
y inc bob work: b
a b decide join: route
operator split-authority
