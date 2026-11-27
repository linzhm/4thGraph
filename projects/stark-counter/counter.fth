REQUIRE ../proof-counter/counter.fth

: counter-block ( u32 -- u32 )
    #1023 #0 ?DO advance LOOP ;
