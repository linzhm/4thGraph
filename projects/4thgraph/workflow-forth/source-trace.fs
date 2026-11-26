\ Loaded by the Python builder in its private Gforth process. Addresses
\ identify dictionary entries only during this run, never in a build artifact.
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
: .call ( nt -- ) ." call " latestxt trace-number name>int trace-number trace-position ;
: trace-word ( -- )
  DEFERS before-word
  STATE @ IF
    >IN @ >R PARSE-NAME find-name R> >IN !
    ?DUP IF ['] .call trace-file outfile-execute THEN
  THEN ;
' trace-definition IS :-hook
' trace-word IS before-word
' trace-refill file-refill-slot !
PREVIOUS DEFINITIONS

: 4thgraph-trace-binding ( addr u xt -- )
  [ ALSO 4thgraph-source-trace ] trace-binding [ PREVIOUS ] ;
