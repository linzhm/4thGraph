( The circuit computes the next u32. This word selects its successor. )
: decide ( u32 -- route ) 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;
