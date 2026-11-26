( P-256 projective kernels. Inputs and outputs are ordered bottom to top. )
( p is the positive field modulus, b3 is three times the curve coefficient b. )
( Coordinates and temporary integers use ScriptNum, with signed output residues. )

bsv-effect: p256-add script-int script-int script-int script-int script-int script-int script-int script-int -- script-int script-int script-int script-int script-int ;
: p256-add  ( p b3 x1 y1 z1 x2 y2 z2 -- p b3 X Y Z )
    int-pick-4 int-pick-2 int*                              ( yy = y1*y2 )
    int-pick-4 int-pick-2 int*                              ( zz = z1*z2 )
    -3 cell>int over int*                                   ( azz = -3*zz )
    int-pick-8 int-pick-6 int*                              ( xx = x1*x2 )
    3 cell>int over int* int-pick-2 int+                     ( t = 3*xx+azz )

    int-pick-9 int-pick-9 int+ int-pick-7 int-pick-7 int+
    int* int-pick-5 int- int-pick-4 int-                     ( yz = [y1+z1]*[y2+z2]-yy-zz )
    int-pick-11 int-roll-11 int+ int-pick-9 int-roll-9 int+
    int* int-pick-3 int- int-pick-6 int-                     ( xy = [x1+y1]*[x2+y2]-xx-yy )
    int-roll-10 int-roll-10 int+ int-roll-9 int-roll-9 int+
    int* int-pick-4 int- int-pick-6 int-                     ( xz = [x1+z1]*[x2+z2]-xx-zz )

    -3 cell>int over int* int-pick-9 int-roll-8 int* int+    ( h = -3*xz+b3*zz )
    int-pick-7 over int+                                     ( plus = yy+h )
    int-roll-8 rot int-                                     ( minus = yy-h )
    int-pick-8 int-roll-3 int* 3 cell>int
    int-roll-7 int-roll-8 int- int* int-                     ( k = b3*xz-3*[xx-azz] )

    int-pick-3 int-pick-2 int* int-pick-5 int-pick-2 int*
    int- int-pick-8 int-rem                                  ( X = xy*minus-yz*k mod p )
    rot int-pick-3 int* int-pick-6 int-roll-3 int*
    int+ int-pick-7 int-rem                                  ( Y = minus*plus+t*k mod p )
    int-roll-4 int-roll-3 int* int-roll-3 int-roll-4 int*
    int+ int-pick-4 int-rem                                  ( Z = yz*plus+xy*t mod p )
;

bsv-effect: p256-double script-int script-int script-int script-int script-int -- script-int script-int script-int script-int script-int ;
: p256-double  ( p b3 x y z -- p b3 X Y Z )
    dup int-nonzero? if                                     ( z = 0 preserves the input point )
        2dup int* dup int+                                  ( s = 2*y*z )
        dup over int* over int* int-pick-6 int-rem           ( Z = s^3 mod p )
        int-roll-3 int-pick-2 int*                           ( r = y*s )
        int-pick-4 over int* dup int+                         ( b = 2*x*r )
        3 cell>int int-pick-6 int-pick-6 int-
        int-roll-7 int-roll-7 int+ int* int*                  ( w = 3 times x-z times x+z )
        dup over int* int-pick-2 dup int+ int-                ( h = w^2-2*b )
        rot over int- rot int* int-pick-2 int-roll-3 int*
        dup int+ int- int-pick-5 int-rem                     ( Y = [b-h]*w-2*r^2 mod p )
        swap int-roll-3 int* int-pick-4 int-rem              ( X = h*s mod p )
        swap rot                                             ( p b3 X Y Z )
    then
;
