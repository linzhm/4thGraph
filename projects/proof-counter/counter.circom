pragma circom 2.2.2;

template Bits32() {
    signal input value;
    signal bits[32];
    var reconstructed = 0;
    for (var i = 0; i < 32; i++) {
        bits[i] <-- (value >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        reconstructed += bits[i] * (1 << i);
    }
    value === reconstructed;
}

template Counter() {
    signal input current;
    signal input bindLo;
    signal input bindHi;
    signal output next;
    signal carry;
    signal bindingProduct;
    carry <-- current == 4294967295;
    carry * (carry - 1) === 0;
    next <== current + 1 - carry * 4294967296;
    bindingProduct <== bindLo * bindHi;
    component from = Bits32();
    component to = Bits32();
    from.value <== current;
    to.value <== next;
}

component main {public [current, bindLo, bindHi]} = Counter();
