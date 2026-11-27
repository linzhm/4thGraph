REQUIRE BSV

: field-coordinate ( bytes -- script-int )
    32 bytes-check-size uint256be
    dup field-prime int< verify
;

: even-coordinate ( bytes -- script-int )
    field-coordinate dup  2 cell>int int-rem  0 cell>int int= verify
;

: checked-scalar ( bytes -- script-int )
    uint256be dup group-order int< verify
;

: signature-halves ( bytes -- bytes bytes )
    64 bytes-check-size 32 op_split
;

: challenge ( bytes bytes bytes -- script-int )
    ( Input order: message, public x, nonce x. )
    bytes-hex 7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c
    dup bytes-cat swap bytes-cat swap bytes-cat swap bytes-cat
    bytes-sha256 uint256be group-order int-rem
;

: next-bit ( script-int script-int -- script-int cell )
    ( With h = 2^255, read the top bit of k and shift the remaining bits left. )
    2dup swap int< IF
        nip 2 cell>int int* 0
    ELSE
        swap int- 2 cell>int int* 1
    THEN
;

: add-if-bit ( script-int script-int script-int script-int script-int script-int script-int script-int --
               script-int script-int script-int script-int script-int )
    expose-scalar next-bit IF
        with-base 1 cell>int add-points
    ELSE
        without-base
    THEN
;

: double-accumulator ( script-int script-int script-int script-int --
                       script-int script-int script-int script-int )
    op_3dup add-points
;

: binary-round ( script-int script-int script-int script-int script-int script-int script-int
                 script-int script-int script-int script-int --
                 script-int script-int script-int script-int script-int script-int script-int
                 script-int script-int script-int script-int )
    ( State: threshold Gx Gy Px Py s k p X Y Z. )
    double-accumulator
    fixed-bit add-if-bit
    variable-bit add-if-bit
;

: multiply-256 ( script-int script-int script-int script-int script-int script-int script-int
                 script-int script-int script-int script-int --
                 script-int script-int script-int script-int )
    256 0 DO binary-round LOOP
    discard-scalar-state
;

: check-curve ( script-int script-int script-int -- )
    curve-residual 0 cell>int int= verify
;

: check-nonce ( script-int script-int script-int script-int script-int script-int -- )
    nonce-residuals
    0 cell>int int= verify
    0 cell>int int= verify
    0 cell>int int= IF 0 ELSE 1 THEN verify
;

lock: reference-bip340 ( message:bytes public-x:bytes public-y:bytes signature:bytes nonce-y:bytes )
    field-prime public-x field-coordinate public-y even-coordinate check-curve

    signature signature-halves drop field-coordinate
    nonce-y even-coordinate

    scalar-threshold generator-x generator-y public-x field-coordinate public-y even-coordinate
    signature signature-halves nip checked-scalar
    group-order message public-x signature signature-halves drop challenge int-
    field-prime 0 cell>int 1 cell>int 0 cell>int
    multiply-256 check-nonce
    1
;
