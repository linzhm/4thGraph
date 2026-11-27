( Jacobian doubling on the a=0 twist over Fp2. Inputs and results are X, Y, Z. )
layout: double-yy ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 --
    x y z y )
layout: double-xx ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 --
    x y z yy x )
layout: double-xyy ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 m:bn254-fp2 --
    y z yy m x yy )
layout: double-mm ( y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 m:bn254-fp2 d:bn254-fp2 --
    y z yy m d m )
layout: double-twod ( y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 m:bn254-fp2 d:bn254-fp2 mm:bn254-fp2 --
    y z yy m d mm d )
layout: double-dx ( y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 m:bn254-fp2 d:bn254-fp2 rx:bn254-fp2 --
    y z yy m rx d rx )
layout: double-mdx ( y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 m:bn254-fp2 rx:bn254-fp2 dx:bn254-fp2 --
    y z yy rx m dx )
layout: double-yyyy ( y:bn254-fp2 z:bn254-fp2 yy:bn254-fp2 rx:bn254-fp2 mdx:bn254-fp2 --
    y z rx mdx yy )
layout: double-yz ( y:bn254-fp2 z:bn254-fp2 rx:bn254-fp2 ry:bn254-fp2 --
    rx ry y z )

: bn254-jacobian-double ( bn254-fp2 bn254-fp2 bn254-fp2 -- bn254-fp2 bn254-fp2 bn254-fp2 )
    double-yy bn254-fp2-square
    double-xx bn254-fp2-square
    bn254-fp2-times-three
    double-xyy bn254-fp2-multiply
    bn254-fp2-times-four
    double-mm bn254-fp2-square
    double-twod bn254-fp2-times-two
    bn254-fp2-subtract
    double-dx bn254-fp2-subtract
    double-mdx bn254-fp2-multiply
    double-yyyy bn254-fp2-square
    bn254-fp2-times-eight
    bn254-fp2-subtract
    double-yz bn254-fp2-multiply
    bn254-fp2-times-two
;

( Mixed addition of Jacobian X, Y, Z and affine Qx, Qy over Fp2. )
layout: mixed-zz ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 qx:bn254-fp2 qy:bn254-fp2 --
    x y z qx qy z )
layout: mixed-qx-zz ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 qx:bn254-fp2 qy:bn254-fp2 zz:bn254-fp2 --
    x y z qy zz qx zz )
layout: mixed-h ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 qy:bn254-fp2 zz:bn254-fp2 qx-zz:bn254-fp2 --
    x y z qy zz qx-zz x )
layout: mixed-zzz ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 qy:bn254-fp2 zz:bn254-fp2 h:bn254-fp2 --
    x y z qy h zz z )
layout: mixed-qy-zzz ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 qy:bn254-fp2 h:bn254-fp2 zzz:bn254-fp2 --
    x y z h qy zzz )
layout: mixed-m ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 qy-zzz:bn254-fp2 --
    x y z h qy-zzz y )
layout: mixed-hh ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 --
    x y z h m h )
layout: mixed-hhh ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hh:bn254-fp2 --
    x y z h m hh h hh )
layout: mixed-v ( x:bn254-fp2 y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hh:bn254-fp2 hhh:bn254-fp2 --
    y z h m hhh x hh )
layout: mixed-mm ( y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hhh:bn254-fp2 v:bn254-fp2 --
    y z h m hhh v m )
layout: mixed-mm-hhh ( y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hhh:bn254-fp2 v:bn254-fp2 mm:bn254-fp2 --
    y z h m hhh v mm hhh )
layout: mixed-twov ( y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hhh:bn254-fp2 v:bn254-fp2 mm-hhh:bn254-fp2 --
    y z h m hhh v mm-hhh v )
layout: mixed-vx ( y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hhh:bn254-fp2 v:bn254-fp2 rx:bn254-fp2 --
    y z h m hhh rx v rx )
layout: mixed-mvx ( y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 m:bn254-fp2 hhh:bn254-fp2 rx:bn254-fp2 vx:bn254-fp2 --
    y z h hhh rx m vx )
layout: mixed-yhhh ( y:bn254-fp2 z:bn254-fp2 h:bn254-fp2 hhh:bn254-fp2 rx:bn254-fp2 mvx:bn254-fp2 --
    z h rx mvx y hhh )
layout: mixed-rz ( z:bn254-fp2 h:bn254-fp2 rx:bn254-fp2 ry:bn254-fp2 --
    rx ry z h )

: bn254-jacobian-mixed-add ( bn254-fp2 bn254-fp2 bn254-fp2 bn254-fp2 bn254-fp2 -- bn254-fp2 bn254-fp2 bn254-fp2 )
    mixed-zz bn254-fp2-square
    mixed-qx-zz bn254-fp2-multiply
    mixed-h bn254-fp2-subtract
    mixed-zzz bn254-fp2-multiply
    mixed-qy-zzz bn254-fp2-multiply
    mixed-m bn254-fp2-subtract
    mixed-hh bn254-fp2-square
    mixed-hhh bn254-fp2-multiply
    mixed-v bn254-fp2-multiply
    mixed-mm bn254-fp2-square
    mixed-mm-hhh bn254-fp2-subtract
    mixed-twov bn254-fp2-times-two
    bn254-fp2-subtract
    mixed-vx bn254-fp2-subtract
    mixed-mvx bn254-fp2-multiply
    mixed-yhhh bn254-fp2-multiply
    bn254-fp2-subtract
    mixed-rz bn254-fp2-multiply
;
