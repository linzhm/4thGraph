( Shared preparation for both table layouts. The four lanes become 64 index pairs. )
layout: expose-lanes ( s:script-int tv:bytes k1:script-int k2:script-int -- tv k1 k2 s )
layout: expose-public ( px:script-int py:script-int s:script-int k:script-int -- s k px py )
layout: restore-public ( s:script-int k:script-int px:script-int py:script-int -- px py s k )

: prepare-windows ( script-int script-int script-int script-int -- bytes bytes )
    expose-public map-public restore-public
    field-prime joint-variable split-glv keep-split signed-variable-table restore-split
    int-abs swap int-abs swap expose-lanes split-fixed 2swap pack-windows
;

: read-window ( bytes -- bytes script-int script-int )
    1 op_split swap dup 4 bytes-rshift bytes>int
    swap 4 bytes-lshift 4 bytes-rshift bytes>int
;

: packed-fixed-add ( script-int script-int script-int script-int bytes script-int --
                     script-int script-int script-int script-int )
    dup 0 cell>int int= IF 2drop ELSE
        66 cell>int int* split-at nip 66 op_split drop
        33 op_split swap bytes>int swap bytes>int add-fixed-affine
    THEN
;

: packed-variable-add ( script-int script-int script-int script-int bytes script-int --
                        script-int script-int script-int script-int )
    dup 0 cell>int int= IF 2drop ELSE window-point add-points THEN
;

layout: packed-start ( tv:bytes digits:bytes tf:bytes -- tf tv digits )
layout: packed-expose ( tf:bytes tv:bytes ds:bytes p:script-int x:script-int y:script-int z:script-int --
                        tf tv p x y z ds )
layout: packed-fixed ( tf:bytes tv:bytes p:script-int x:script-int y:script-int z:script-int
                       ds:bytes v:script-int f:script-int -- tf tv ds v p x y z tf f )
layout: packed-variable ( tf:bytes tv:bytes ds:bytes v:script-int p:script-int x:script-int y:script-int z:script-int --
                          tf tv ds p x y z tv v )
layout: packed-result ( tf:bytes tv:bytes ds:bytes p:script-int x:script-int y:script-int z:script-int -- p x y z )

: packed-step ( bytes bytes bytes script-int script-int script-int script-int --
                 bytes bytes bytes script-int script-int script-int script-int )
    double-pair packed-expose read-window
    packed-fixed packed-fixed-add packed-variable packed-variable-add
;

: packed-joint ( script-int script-int script-int script-int -- script-int script-int script-int script-int )
    prepare-windows fixed-affine-table packed-start
    field-prime 0 cell>int 1 cell>int 0 cell>int
    64 0 DO packed-step LOOP
    packed-result restore-model
;
