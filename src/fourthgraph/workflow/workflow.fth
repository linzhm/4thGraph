( Build-time workflow records. Loaded with REQUIRE by the workflow source. )
BASE @ DECIMAL
REQUIRE ./rule-words.fth

: text, ( c-addr u -- ) DUP , HERE OVER CHARS ALLOT SWAP CHARS MOVE ALIGN ;
: named-create ( "name" -- )
  >IN @ PARSE-NAME ROT >IN ! CREATE text, ;
: record-name ( record -- c-addr u ) DUP CELL+ SWAP @ ;
: record-data ( record -- a-addr ) record-name CHARS + ALIGNED ;
: slot@ ( a-addr index -- x ) CELLS + @ ;
: name. ( record -- ) record-name TYPE SPACE ;

: list: ( x1 ... xn n "name" -- )
  DUP 0< ABORT" negative list length" CREATE DUP , 0 ?DO , LOOP ;
: list. ( list -- )
  DUP @ DUP . 0 ?DO DUP DUP @ I - slot@ . LOOP DROP ;

: role: ( "name" -- ) named-create ;
: relation-ref ( "word" -- relation )
  >IN @ PARSE-NAME ROT >IN ! ' HERE >R , text, R> ;
: relation-xt ( relation -- xt ) @ ;

0 CONSTANT direct-script
1 CONSTANT proof-required
2 CONSTANT groth16-required
0 CONSTANT no-amount
1 CONSTANT signed-amount
2 CONSTANT parent-amount
65 CONSTANT forkid-all
97 CONSTANT otda-all

: context: ( sighash-list amount-policy "name" -- ) CREATE , , ;
5 CONSTANT selector-fields
: selector: ( kind min max first limit "name" -- ) CREATE selector-fields 0 DO , LOOP ;
: ordered: ( min max "name" -- ) 0 -ROT 0 0 selector: ;
: at-range: ( min max first limit "name" -- ) 2>R 1 -ROT 2R> selector: ;
: current: ( min max "name" -- ) 2 -ROT 0 0 selector: ;
: paired: ( min max "name" -- ) 3 -ROT 0 0 selector: ;
: unselected: ( "name" -- ) 4 0 -1 0 0 selector: ;
: selector. ( selector -- ) selector-fields 0 DO DUP selector-fields 1- I - slot@ . LOOP DROP ;

: stage: ( inputs outputs in-selector out-selector relation role context policy "name" -- )
  named-create 8 0 DO , LOOP ;

: emit-roots ( resources -- )
  BASE @ >R DECIMAL S" roots " TYPE list. CR R> BASE ! ;

: emit-stage ( stage -- )
  BASE @ >R DECIMAL
  [DEFINED] 4thgraph-trace-binding [IF]
    DUP record-name 2 PICK record-data 3 slot@ relation-xt 4thgraph-trace-binding
  [THEN]
  S" stage " TYPE DUP name. record-data
  DUP 3 slot@ CELL+ name. DUP 2 slot@ name.
  DUP @ . DUP 1 slot@ DUP @ . 1 slot@ list.
  DUP 5 slot@ selector. DUP 4 slot@ selector.
  DUP 7 slot@ list. 6 slot@ list. CR
  R> BASE ! ;

: emit-stages ( stage1 ... stage-n n -- ) 0 ?DO emit-stage LOOP ;

BASE !
