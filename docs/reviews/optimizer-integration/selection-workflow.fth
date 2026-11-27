REQUIRE BSV

( The labels 3 and 9 represent draft and ready. )
: prepare-status ( u32 -- u32 )
    u32>cell 3 = IF 9 ELSE 3 THEN cell>u32
;

: route-status ( u32 -- route )
    u32>cell 9 = IF route-settle ELSE route-review THEN
;

workflow-input: status u32 ;
stage: prepare prepare-status status next operator ;
stage: finish route-status next route bob ;
