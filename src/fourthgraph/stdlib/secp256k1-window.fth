REQUIRE BSV
REQUIRE stdlib/script-fragments.fth

range: secp-window-coordinate script-int $-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                                         $10000000000000000000000000000000000000000000000000000000000000000 ;
range: secp-window-field script-int 2 $10000000000000000000000000000000000000000000000000000000000000000 ;
range: secp-window-sign script-int -1 2 ;

( Q starts with the signed affine ordinate. Its x and the two projective
  x coordinates use the same endomorphism constant and field modulus. )
formula: secp-window-map-row-coordinates ( secp-window-field secp-window-coordinate
    secp-window-coordinate secp-window-coordinate secp-window-coordinate
    secp-window-coordinate secp-window-coordinate secp-window-coordinate
    secp-window-coordinate secp-window-sign secp-window-coordinate --
    secp-window-coordinate secp-window-coordinate secp-window-coordinate
    secp-window-coordinate secp-window-coordinate secp-window-coordinate
    secp-window-coordinate secp-window-coordinate secp-window-coordinate )
    {: p x x2 y2 z2 x3 y3 z3 qy sign beta :}
    x beta int* p int-rem qy 1
    x2 beta int* p int-rem y2 sign int* z2
    x3 beta int* p int-rem y3 sign int* z3
;

( Pack four secp256k1 GLV lanes and read the associated table depths. )
: secp-window-uint128le ( script -- script )
    ( The magnitude is below 2^128. Drop the separate positive sign byte. )
    17 bsv-num op-num2bin op-16 op-split op-drop
;

: secp-window-pack-windows ( script -- script )
    ( s0 s1 abs-k1 abs-k2 -> 64 bytes with one fixed and one variable index per window. )
    secp-window-uint128le bsv-empty op-swap secp-window-uint128le op-cat 3 script-append-repeated
    ( Digit positions are numbered from the low end of the 512-bit string. )
    ( Transpose lane and digit bits. The first four swaps also reverse little-endian byte order. )
    ( Swap position bits 4 and 6, complementing both. )
    160 bsv-empty op-0 20 bsv-num op-num2bin bytes-hex ffffffff00000000ffffffff bsv-push op-cat
    1 script-repeat-mask-code script-swap-bit-groups
    ( Swap position bits 5 and 7, complementing both. )
    320 bsv-empty op-0 40 bsv-num op-num2bin
    op-0 op-8 op-num2bin op-dup op-invert op-tuck op-cat op-cat op-cat script-swap-bit-groups
    ( Swap position bits 2 and 4, complementing both. )
    40 bytes-hex 0000000000ff00ff 3 script-repeat-mask script-swap-bit-groups
    ( Swap position bits 3 and 5, complementing both. )
    80 bsv-empty op-0 op-10 op-num2bin bytes-hex ffff0000ffff bsv-push op-cat
    2 script-repeat-mask-code script-swap-bit-groups
    ( Swap position bits 0 and 2. )
    6 bytes-hex 00cc 5 script-repeat-mask script-swap-bit-groups
    ( Swap position bits 1 and 3. )
    12 bytes-hex 0000f0f0 4 script-repeat-mask script-swap-bit-groups
;

: secp-window-nonzero-window-digits ( script -- script )
    ( Leave the input and a ScriptNum whose bytes are 1 where the input digit was nonzero. )
    ( The two shifts and ORs move any of the four bits into bit zero of its byte. )
    op-dup op-dup op-2 op-rshift op-or op-dup op-1 op-rshift op-or
    bytes-hex 01 7 script-repeat-mask bsv-cat-code op-and op-bin2num
;

: secp-window-spread-window-blocks ( script cell cell -- script )
    ( Move the upper half of each live block into the reserved zeros. )
    ( Build arguments: block width in bytes and mask repetition doublings. )
    over rot rot script-block-mask rot op-dup rot
    8 * bsv-num op-lshift op-or swap bsv-cat-code op-and
;

: secp-window-expand-window-digits ( script -- script )
    ( Insert a zero byte before each packed nibble pair. )
    op-0 64 bsv-num op-num2bin op-swap op-cat
    32 1 secp-window-spread-window-blocks 16 2 secp-window-spread-window-blocks
    8 3 secp-window-spread-window-blocks 4 4 secp-window-spread-window-blocks
    2 5 secp-window-spread-window-blocks 1 6 secp-window-spread-window-blocks
    ( Move the high nibble into that byte. Return variable, fixed pairs. )
    op-dup op-4 op-lshift op-or bytes-hex 0f 7 script-repeat-mask bsv-cat-code op-and
;

: secp-window-window-depths ( script -- script )
    secp-window-expand-window-digits secp-window-nonzero-window-digits op-swap op-bin2num
    ( For digit i and presence m, first compute the variable correction 79*m-5*i. )
    op-2dup op-5 op-mul op-swap 79 bsv-num op-mul op-swap op-sub 128 bsv-num op-num2bin
    bytes-hex ff00 6 script-repeat-mask bsv-cat-code op-and op-bin2num
    ( Add the common depth 3*m+2*i. The byte lanes neither carry nor borrow. )
    op-swap op-2 op-mul op-add op-swap op-3 op-mul op-add 128 bsv-num op-num2bin
;

: secp-window-pick-variable-point ( script -- script )
    ( Replace a nonzero lookup depth with the selected X, Y and Z. )
    op-dup op-pick op-over op-pick op-rot op-1sub op-pick
;

: secp-window-read-window ( script -- script )
    ( Read the pair in one split, then split just those two bytes. )
    ( A nonzero depth is a minimal positive ScriptNum, and a zero byte skips addition. )
    op-fromaltstack op-2 op-split op-toaltstack op-1 op-split op-toaltstack
;
