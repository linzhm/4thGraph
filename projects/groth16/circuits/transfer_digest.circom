pragma circom 2.2.3;

include "sha256_bytes.circom";

template CompactTransferDigest() {
    signal input preimage[192];
    signal input issuance[36];
    signal input digestHigh;
    signal input digestLow;
    var domain[24] = [66, 83, 86, 47, 71, 114, 111, 116, 104, 49, 54, 47, 116, 114, 97, 110, 115, 102, 101, 114, 47, 118, 50, 0];
    component inner = Hash256Bytes(192);
    for (var i = 0; i < 192; i++) inner.data[i] <== preimage[i];
    preimage[188] === 65;
    for (var i = 189; i < 192; i++) preimage[i] === 0;
    component outer = Hash256Bytes(92);
    for (var i = 0; i < 24; i++) outer.data[i] <== domain[i];
    for (var i = 0; i < 36; i++) outer.data[i+24] <== issuance[i];
    for (var i = 0; i < 32; i++) outer.data[i+60] <== inner.digest[i];
    var high = 0;
    var low = 0;
    for (var i = 0; i < 16; i++) {
        high = 256*high + outer.digest[i];
        low = 256*low + outer.digest[i+16];
    }
    digestHigh === high;
    digestLow === low;
}
