pragma circom 2.2.3;

include "../../groth16/circuits/sha256_bytes.circom";

template StatementDigest(domain, prefix, length) {
    signal input payload[length];
    signal input digestHigh;
    signal input digestLow;
    component digest = Hash256Bytes(prefix + length);
    for (var i = 0; i < prefix; i++) digest.data[i] <== domain[i];
    for (var i = 0; i < length; i++) digest.data[prefix+i] <== payload[i];
    var high = 0;
    var low = 0;
    for (var i = 0; i < 16; i++) {
        high = 256 * high + digest.digest[i];
        low = 256 * low + digest.digest[16+i];
    }
    digestHigh === high;
    digestLow === low;
}
