REQUIRE workflow.fth

( Host definitions of the 4thGraph primitives used by the shared rules. )
: cell>u32 ( n -- u ) 4294967295 AND ;
: u32+ ( u u -- u ) + cell>u32 ;
: u32< ( u u -- flag ) U< ;
0 CONSTANT route-review
1 CONSTANT route-settle
REQUIRE counter-rules.fth

0 CONSTANT deposit
1 CONSTANT pending
2 CONSTANT payment
3 CONSTANT receipt

deposit  1 list: root-resources
pending  1 list: pending-resources
payment receipt 2 list: terminal-resources

1 1 ordered: one-item
2 2 ordered: two-items
forkid-all 1 list: modes
modes no-amount context: forkid-context
role: operator
role: bob

root-resources pending-resources one-item one-item
  relation-ref advance operator forkid-context direct-script stage: prepare
pending-resources terminal-resources one-item two-items
  relation-ref decide bob forkid-context direct-script stage: settle

root-resources emit-roots
settle emit-stage
prepare emit-stage
