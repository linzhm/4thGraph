( Prepare signed bases and leave the digit stream above them. )
layout: retain-signs ( s:script-int p:script-int px:script-int py:script-int k1:script-int k2:script-int --
                      s k1 k2 p px py k1 k2 )
layout: restore-signs ( s:script-int k1:script-int k2:script-int
                        p:script-int px:script-int py:script-int qx:script-int qy:script-int --
                        p px py qx qy s k1 k2 )

: pack-signed-bases ( script-int script-int script-int script-int script-int --
                      script-int script-int script-int script-int script-int bytes )
    split-glv retain-signs signed-bases restore-signs
    int-abs swap int-abs swap rot split-fixed 2swap pack-windows
;

: prepare-stack-windows ( script-int script-int script-int script-int --
                           script-int script-int script-int script-int script-int bytes )
    map-public pack-signed-bases
;

: prepare-mapped-windows ( script-int script-int script-int script-int script-int --
                            script-int script-int script-int script-int script-int bytes )
    joint-variable pack-signed-bases
;

( Input order: p, 2P, 3P, Py, Qy. The endomorphism leaves the nonzero affine
  ordinate unchanged, so comparing Py and Qy gives one sign for both rows. )
: map-row-pair ( script-int script-int script-int script-int script-int script-int script-int script-int script-int --
                 script-int script-int script-int script-int script-int script-int )
    int= IF 1 ELSE -1 THEN cell>int glv-beta map-row-coordinates
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
