( Prepare the signed ordinates and the digit stream. The table computes Qx. )
layout: retain-signs ( s:script-int p:script-int px:script-int py:script-int k1:script-int k2:script-int --
                      s k1 k2 p px py k1 k2 )
layout: restore-signs ( s:script-int k1:script-int k2:script-int
                        p:script-int px:script-int py:script-int qy:script-int --
                        p px py qy s k1 k2 )
layout: second-ordinate ( p:script-int px:script-int py:script-int k2:script-int signed-y:script-int --
                          p px signed-y py k2 )

: signed-row-ordinates ( script-int script-int script-int script-int script-int --
                         script-int script-int script-int script-int )
    signed-p sign-ordinate second-ordinate sign-ordinate
;

: pack-row-ordinates ( script-int script-int script-int script-int script-int script-int --
                       script-int script-int script-int script-int bytes )
    retain-signs signed-row-ordinates restore-signs
    int-abs swap int-abs swap pack-fixed-scalar-windows
;

: prepare-stack-windows ( script-int script-int script-int script-int --
                           script-int script-int script-int script-int bytes )
    map-public split-glv pack-row-ordinates
;

: prepare-mapped-windows ( script-int script-int script-int script-int script-int --
                            script-int script-int script-int script-int bytes )
    joint-variable split-glv pack-row-ordinates
;

layout: joint-variable-with-order ( px:script-int py:script-int p:script-int s:script-int k:script-int n:script-int --
                                    s p px py k n )

: prepare-mapped-windows-with-order ( script-int script-int script-int script-int script-int script-int --
                                       script-int script-int script-int script-int bytes )
    joint-variable-with-order split-glv-with-order pack-row-ordinates
;

( Input order: p, Px, 2P, 3P, Qy, Py. The endomorphism leaves the nonzero
  affine ordinate unchanged, so comparing the signed ordinates gives the relative sign. )
: map-row-starts ( script-int script-int script-int script-int script-int script-int script-int script-int script-int script-int --
                   script-int script-int script-int script-int script-int script-int script-int script-int script-int )
    over int= IF 1 ELSE -1 THEN cell>int glv-beta map-row-coordinates
;

( Input: p, Px, X2, Y2, X3, Y3, Qy, Py. Return Q2y, Q3y, Qx, Q2x, Q3x. )
: map-row-components ( script-int script-int script-int script-int script-int script-int script-int script-int --
                       script-int script-int script-int script-int script-int )
    int= IF 1 ELSE -1 THEN cell>int glv-beta map-glv-components
;

( A row consumes its affine P and projective jQ, and appends four projective entries. )
layout: append-input ( p:script-int px:script-int py:script-int x:script-int y:script-int z:script-int --
                       x y z px py p x y z px py )
layout: preserve-base ( px:script-int py:script-int p:script-int x:script-int y:script-int z:script-int --
                         p px py x y z )
layout: last-entry ( p:script-int px:script-int py:script-int x:script-int y:script-int z:script-int -- x y z )

: advance-row ( script-int script-int script-int script-int script-int script-int --
                script-int script-int script-int script-int script-int script-int script-int script-int script-int )
    append-input add-fixed-affine preserve-base
;

: stack-table-row ( script-int script-int script-int script-int script-int script-int --
                    script-int script-int script-int script-int script-int script-int
                    script-int script-int script-int script-int script-int script-int )
    3 0 DO advance-row LOOP last-entry
;
