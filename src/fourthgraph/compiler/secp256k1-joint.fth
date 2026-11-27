REQUIRE BSV

: bits-2 ( bytes -- script-int )
    1 op_split drop 6 bytes-rshift bytes>int
;

: next-window ( bytes -- bytes script-int )
    ( Shift a pair of 128-bit lanes left. Spill from the low lane cannot reach
      the high lane's leading two bits until after the last of the 64 windows. )
    dup 2 bytes-lshift swap 16 op_split
    bits-2 swap bits-2 4 cell>int int* int+
;

: pack-lanes ( script-int script-int -- bytes )
    ( The 32-byte result is high lane then low lane, both big-endian. )
    lane>bytes swap lane>bytes swap bytes-cat reverse-32
;

: split-fixed ( script-int -- script-int script-int )
    dup half-radix int-div swap half-radix int-rem swap
;

: encode-point ( script-int script-int script-int -- bytes )
    residue>bytes swap residue>bytes swap bytes-cat
    swap residue>bytes swap bytes-cat
;

: decode-point ( bytes -- script-int script-int script-int )
    33 op_split swap bytes>int swap
    33 op_split swap bytes>int swap bytes>int
;

: window-point ( bytes script-int -- script-int script-int script-int )
    99 cell>int int* split-at nip 99 op_split drop decode-point
;

layout: start-rows ( p:script-int px:script-int py:script-int qx:script-int qy:script-int out:bytes --
                      out p px py qx qy )
layout: start-row ( out:bytes p:script-int px:script-int py:script-int qx:script-int qy:script-int
                    rx:script-int ry:script-int rz:script-int -- out p px py qx qy rx ry rz rx ry rz )
layout: take-row-point ( out:bytes p:script-int px:script-int py:script-int qx:script-int qy:script-int
                         rx:script-int ry:script-int rz:script-int sx:script-int sy:script-int sz:script-int --
                         p px py qx qy rx ry rz sx sy sz out sx sy sz )
layout: restore-row ( p:script-int px:script-int py:script-int qx:script-int qy:script-int
                      rx:script-int ry:script-int rz:script-int sx:script-int sy:script-int sz:script-int out:bytes --
                      out p px py qx qy rx ry rz sx sy sz )
layout: add-row-p ( out:bytes p:script-int px:script-int py:script-int qx:script-int qy:script-int
                     rx:script-int ry:script-int rz:script-int sx:script-int sy:script-int sz:script-int --
                     out p px py qx qy rx ry rz p sx sy sz px py )
layout: keep-row-point ( out:bytes p:script-int px:script-int py:script-int qx:script-int qy:script-int
                         rx:script-int ry:script-int rz:script-int unused:script-int sx:script-int sy:script-int sz:script-int --
                         out p px py qx qy rx ry rz sx sy sz )
layout: add-row-q ( out:bytes p:script-int px:script-int py:script-int qx:script-int qy:script-int
                     rx:script-int ry:script-int rz:script-int -- out px py qx qy p rx ry rz qx qy )
layout: restore-rows ( out:bytes px:script-int py:script-int qx:script-int qy:script-int
                       p:script-int rx:script-int ry:script-int rz:script-int -- out p px py qx qy rx ry rz )
layout: rows-result ( out:bytes p:script-int px:script-int py:script-int qx:script-int qy:script-int
                      rx:script-int ry:script-int rz:script-int -- out )

: append-row-point ( bytes script-int script-int script-int script-int script-int script-int script-int script-int
                     script-int script-int script-int --
                     bytes script-int script-int script-int script-int script-int script-int script-int script-int
                     script-int script-int script-int )
    take-row-point encode-point bytes-cat restore-row
;

: build-row ( bytes script-int script-int script-int script-int script-int script-int script-int script-int --
              bytes script-int script-int script-int script-int script-int script-int script-int script-int )
    ( Each row starts at jQ and records jQ + iP for i = 0..3. )
    start-row
    3 0 DO
        append-row-point add-row-p 1 cell>int add-points keep-row-point
    LOOP
    append-row-point 2drop drop
;

: variable-table ( script-int script-int script-int script-int script-int -- bytes )
    empty-bytes start-rows 0 cell>int 1 cell>int 0 cell>int
    3 0 DO
        build-row add-row-q 1 cell>int add-points restore-rows
    LOOP
    build-row rows-result
;

: sign-ordinate ( script-int script-int -- script-int )
    0 cell>int int< IF int-negate THEN
;

layout: signed-p ( p:script-int px:script-int py:script-int k1:script-int k2:script-int --
                    p px py k2 py k1 )
layout: phi-x-input ( p:script-int px:script-int py:script-int k2:script-int signed-y:script-int --
                       p px signed-y py k2 px p )
layout: phi-y-input ( p:script-int px:script-int signed-y:script-int py:script-int
                       k2:script-int qx:script-int -- p px signed-y qx py k2 )

: signed-bases ( script-int script-int script-int script-int script-int --
                 script-int script-int script-int script-int script-int )
    signed-p sign-ordinate
    phi-x-input swap glv-beta int* swap int-rem
    phi-y-input sign-ordinate
;

: signed-variable-table ( script-int script-int script-int script-int script-int -- bytes )
    signed-bases variable-table
;

layout: keep-split ( p:script-int px:script-int py:script-int k1:script-int k2:script-int --
                     k1 k2 p px py k1 k2 )
layout: restore-split ( k1:script-int k2:script-int table:bytes -- table k1 k2 )

: setup-variable ( script-int script-int script-int script-int -- bytes bytes )
    split-glv keep-split signed-variable-table restore-split
    int-abs swap int-abs swap pack-lanes
;

layout: window-index-input ( t:bytes shift:bytes index:script-int -- shift t index )

: select-window ( bytes bytes -- bytes script-int script-int script-int )
    next-window window-index-input window-point
;

layout: expose-fixed ( tf:bytes tv:bytes sf:bytes sv:bytes p:script-int x:script-int y:script-int z:script-int --
                       tf tv sv p x y z tf sf )
layout: add-fixed ( tf:bytes tv:bytes sv:bytes p:script-int x:script-int y:script-int z:script-int
                    sf:bytes a:script-int b:script-int c:script-int -- tf tv sf sv p x y z a b c )
layout: expose-variable ( tf:bytes tv:bytes sf:bytes sv:bytes p:script-int x:script-int y:script-int z:script-int --
                          tf tv sf p x y z tv sv )
layout: add-variable ( tf:bytes tv:bytes sf:bytes p:script-int x:script-int y:script-int z:script-int
                       sv:bytes a:script-int b:script-int c:script-int -- tf tv sf sv p x y z a b c )
layout: msm-result ( tf:bytes tv:bytes sf:bytes sv:bytes p:script-int x:script-int y:script-int z:script-int --
                     p x y z )

: window-step ( bytes bytes bytes bytes script-int script-int script-int script-int --
                bytes bytes bytes bytes script-int script-int script-int script-int )
    ( Accumulator = 4*accumulator + fixed[d] + variable[d]. Index zero is infinity. )
    op_3dup add-points op_3dup add-points
    expose-fixed select-window add-fixed add-points
    expose-variable select-window add-variable add-points
;

: multiply-64 ( bytes bytes bytes bytes script-int script-int script-int script-int --
                 script-int script-int script-int script-int )
    64 0 DO window-step LOOP
    msm-result
;

layout: joint-variable ( px:script-int py:script-int s:script-int k:script-int p:script-int -- s p px py k )
layout: joint-fixed ( s:script-int tv:bytes sv:bytes -- tv sv s )
layout: joint-state ( tv:bytes sv:bytes sf:bytes tf:bytes -- tf tv sf sv )

: secp256k1-joint-window-2 ( script-int script-int script-int script-int --
                             script-int script-int script-int script-int )
    ( Checked affine Px Py and scalars s k in 0..n. Return p X Y Z for sG+kP. )
    field-prime joint-variable setup-variable joint-fixed split-fixed pack-lanes
    fixed-window-table joint-state
    field-prime 0 cell>int 1 cell>int 0 cell>int multiply-64
;
