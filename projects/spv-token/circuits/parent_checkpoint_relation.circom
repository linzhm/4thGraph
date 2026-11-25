pragma circom 2.2.3;

include "statement_digest.circom";

template ShaCheckpoint(length, processed) {
    assert(processed % 64 == 0 && processed > 0 && processed <= length);
    signal input data[length];
    signal output midstate[32];
    signal output txid[32];
    var blocks = (length + 72) \ 64;
    var initial[8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    component bytes[length];
    for (var i = 0; i < length; i++) {
        bytes[i] = Unsigned(8);
        bytes[i].value <== data[i];
    }
    component rounds[blocks];
    for (var i = 0; i < blocks; i++) {
        rounds[i] = ShaCompress();
        for (var j = 0; j < 8; j++) {
            if (i == 0) rounds[i].initial[j] <== initial[j];
            else rounds[i].initial[j] <== rounds[i-1].state[j];
        }
        for (var w = 0; w < 16; w++) {
            for (var b = 0; b < 32; b++) {
                var index = i*64 + w*4 + 3 - (b \ 8);
                if (index < length) rounds[i].block[w][b] <== bytes[index].bits[b%8];
                else if (index == length) rounds[i].block[w][b] <== (128 >> (b%8)) & 1;
                else if (index >= blocks*64-8) {
                    rounds[i].block[w][b] <== ((length*8) >> (8*(blocks*64-1-index) + b%8)) & 1;
                } else rounds[i].block[w][b] <== 0;
            }
        }
    }
    component words[2][8];
    signal firstHash[32];
    for (var stage = 0; stage < 2; stage++) {
        var round = stage == 0 ? (processed \ 64) - 1 : blocks - 1;
        for (var i = 0; i < 8; i++) {
            words[stage][i] = Unsigned(32);
            words[stage][i].value <== rounds[round].state[i];
            for (var j = 0; j < 4; j++) {
                var value = 0;
                for (var b = 0; b < 8; b++) value += words[stage][i].bits[(3-j)*8+b] * (1 << b);
                if (stage == 0) midstate[4*i+j] <== value;
                else firstHash[4*i+j] <== value;
            }
        }
    }
    component second = Sha256Bytes(32);
    for (var i = 0; i < 32; i++) second.data[i] <== firstHash[i];
    for (var i = 0; i < 32; i++) txid[i] <== second.digest[i];
}

template ParentCheckpoint(length, processed, outputOffset, count, token) {
    signal input payload[144];
    signal input parent[length];
    signal input digestHigh;
    signal input digestLow;
    component whole = ShaCheckpoint(length, processed);
    for (var i = 0; i < length; i++) whole.data[i] <== parent[i];
    component suffix = Hash256Bytes(length - processed);
    for (var i = 0; i < length - processed; i++) suffix.data[i] <== parent[processed+i];
    for (var i = 0; i < 32; i++) {
        payload[i] === whole.txid[i];
        payload[32+i] === whole.midstate[i];
        payload[80+i] === suffix.digest[i];
    }
    for (var i = 0; i < 8; i++) payload[64+i] === ((processed >> (8*i)) & 255);
    for (var i = 0; i < 4; i++) {
        payload[72+i] === ((outputOffset >> (8*i)) & 255);
        payload[76+i] === ((count >> (8*i)) & 255);
    }
    parent[outputOffset] === count;
    component amounts[count];
    var maxMoney = 21000000 * 100000000;
    for (var index = 0; index < count; index++) {
        var start = outputOffset + 1 + 10*index;
        var sats = 0;
        for (var i = 0; i < 8; i++) sats += parent[start+i] * (1 << (8*i));
        amounts[index] = Unsigned(51);
        amounts[index].value <== maxMoney - sats;
    }
    if (token == 0) {
        parent[4] === 1;
        var fixedInput[6] = [253,3,1,77,0,1];
        for (var i = 0; i < 6; i++) parent[41+i] === fixedInput[i];
        component outputs = Hash256Bytes(20);
        for (var i = 0; i < 20; i++) outputs.data[i] <== parent[outputOffset+1+i];
        for (var i = 0; i < 32; i++) payload[112+i] === outputs.digest[i];
        for (var i = 0; i < count; i++) parent[outputOffset+9+10*i] === 1;
    } else {
        parent[4] === 2;
        parent[41] === 253;
        parent[42] === 246;
        parent[43] === 6;
        parent[outputOffset-5] === 0;
        parent[outputOffset+9] === 253;
        parent[outputOffset+10] === 10;
        parent[outputOffset+11] === 6;
        signal carrier <== maxMoney - amounts[0].value;
        signal carrierInverse <-- carrier == 0 ? 0 : 1/carrier;
        carrier * carrierInverse === 1;
        var marker[20] = [18,66,83,86,47,67,67,84,80,47,116,111,107,101,110,47,118,50,0,74];
        var metadata = outputOffset + 12;
        for (var i = 0; i < 20; i++) parent[metadata+i] === marker[i];
        var firstQuantity = metadata + 52;
        var units = 0;
        for (var i = 0; i < 8; i++) units += parent[firstQuantity+i] * (1 << (8*i));
        signal unitsInverse <-- units == 0 ? 0 : 1/units;
        unitsInverse * units === 1;
        (parent[firstQuantity+8] - 2) * (parent[firstQuantity+8] - 3) === 0;
        parent[firstQuantity+41] === 0;
        for (var i = 0; i < 32; i++) payload[112+i] === 0;
    }
    var domain[30] = [66,83,86,47,67,67,84,80,47,112,97,114,101,110,116,45,99,104,101,99,107,112,111,105,110,116,47,118,49,0];
    component digest = StatementDigest(domain, 30, 144);
    for (var i = 0; i < 144; i++) digest.payload[i] <== payload[i];
    digest.digestHigh <== digestHigh;
    digest.digestLow <== digestLow;
}
