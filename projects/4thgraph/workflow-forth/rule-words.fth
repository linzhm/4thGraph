( Host implementations of the typed scalar and route words used by shared rules. )
1 CELLS #8 <> [IF] .( 4thGraph requires 64-bit Forth cells ) CR -1 THROW [THEN]
: cell>u32 ( n -- u ) $ffffffff AND ;
: u32>cell ( u -- n ) ;
: u32+ ( u u -- u ) + cell>u32 ;
: u32< ( u u -- flag ) U< ;
0 CONSTANT route-review
1 CONSTANT route-settle
