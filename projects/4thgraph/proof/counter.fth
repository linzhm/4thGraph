( The circuit computes the next u32. This word selects its successor. )
bsv-effect: decide u32 -- route ;
: decide 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;
