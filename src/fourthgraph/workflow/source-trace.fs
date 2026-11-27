\ Loaded by the Python builder in its private Gforth process. Addresses
\ identify dictionary entries only during this run, never in a build artifact.
REQUIRE ./rule-words.fth
VOCABULARY 4thgraph-source-trace
ALSO 4thgraph-source-trace DEFINITIONS
S" FOURTHGRAPH_SOURCE_TRACE" getenv w/o create-file throw CONSTANT trace-file
: trace-hex ( addr u -- )
  BASE @ >R HEX BOUNDS ?DO I C@ 0 <# # # #> TYPE LOOP R> BASE ! ;
: trace-number ( n -- ) BASE @ >R DECIMAL . R> BASE ! ;
: trace-position ( -- )
  input-lexeme 2@ DROP SOURCE DROP - trace-number
  sourceline# trace-number sourcefilename trace-hex CR ;
: .binding ( addr u xt -- ) ." binding " trace-number TYPE CR ;
: trace-binding ( addr u xt -- ) ['] .binding trace-file outfile-execute ;

\ Observe the file REFILL used by the interpreter, including lines consumed
\ inside multiline comments. Other input sources retain their normal methods.
' refill >body @ current-input @ @ + CONSTANT file-refill-slot
file-refill-slot @ CONSTANT original-file-refill
: .source-line ( -- )
  ." line " sourceline# trace-number sourcefilename trace-hex SPACE SOURCE trace-hex CR ;
: trace-refill ( -- flag )
  original-file-refill EXECUTE DUP IF ['] .source-line trace-file outfile-execute THEN ;

: .definition ( -- ) ." definition " latestxt trace-number trace-position ;
: trace-definition ( colon-sys -- colon-sys )
  DEFERS :-hook ['] .definition trace-file outfile-execute ;
: .compilation ( nt -- ) name>comp ['] compile, = SWAP trace-number trace-number ;
: .builtin ( addr u nt -- ) ." builtin " .compilation TYPE CR ;
: trace-vocabulary ( "names..." -- )
  BEGIN PARSE-NAME DUP WHILE
    2DUP find-name ?DUP IF ['] .builtin trace-file outfile-execute ELSE 2DROP THEN
  REPEAT 2DROP ;
: .call ( nt -- ) ." call " latestxt trace-number .compilation
  input-lexeme 2@ trace-hex SPACE trace-position ;
: .cell ( n -- ) ." literal " latestxt trace-number trace-number trace-position ;
: trace-token ( addr u -- )
  DUP 0= IF 2DROP EXIT THEN
  2DUP find-name ?DUP IF NIP NIP ['] .call trace-file outfile-execute EXIT THEN
  \ Use the same single-cell number conversion as Gforth's compiler.
  dpl @ >R snumber? R> dpl !
  DUP 0< IF DROP ['] .cell trace-file outfile-execute
  ELSE 0> IF 2DROP THEN THEN ;
: trace-word ( -- )
  DEFERS before-word
  STATE @ IF
    >IN @ >R PARSE-NAME R> >IN ! trace-token
  THEN ;
' trace-definition IS :-hook
' trace-word IS before-word
' trace-refill file-refill-slot !
PREVIOUS DEFINITIONS

: 4thgraph-trace-binding ( addr u xt -- )
  [ ALSO 4thgraph-source-trace ] trace-binding [ PREVIOUS ] ;
: 4thgraph-trace-vocabulary ( "names..." -- )
  [ ALSO 4thgraph-source-trace ] trace-vocabulary [ PREVIOUS ] ;
