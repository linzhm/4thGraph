pragma circom 2.2.3;

include "mimo_relation.circom";

// Words use little-endian bit indices. Input and output bytes use SHA-256 wire order.
template ShaWordAdd(terms, width) {
    signal input words[terms];
    signal output value;
    signal output bits[32];
    component packed = Unsigned(width);
    var sum = 0;
    var low = 0;
    for (var i = 0; i < terms; i++) sum += words[i];
    packed.value <== sum;
    for (var i = 0; i < 32; i++) {
        bits[i] <== packed.bits[i];
        low += bits[i] * (1 << i);
    }
    value <== low;
}

template ShaSigma(r0, r1, r2, shift) {
    signal input bits[32];
    signal output value;
    signal first[32];
    signal result[32];
    var packed = 0;
    for (var i = 0; i < 32; i++) {
        var x = bits[(i+r0)%32];
        var y = bits[(i+r1)%32];
        var z = 0;
        if (shift == 0 || i+r2 < 32) z = bits[(i+r2)%32];
        first[i] <== x+y-2*x*y;
        result[i] <== first[i]+z-2*first[i]*z;
        packed += result[i] * (1 << i);
    }
    value <== packed;
}

template ShaCompress() {
    signal input block[16][32];
    signal input initial[8];
    signal output state[8];
    var k[64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    signal w[64];
    signal wb[64][32];
    component schedule0[48];
    component schedule1[48];
    component schedule[48];
    for (var i = 0; i < 64; i++) {
        if (i < 16) {
            var word = 0;
            for (var j = 0; j < 32; j++) {
                wb[i][j] <== block[i][j];
                word += block[i][j] * (1 << j);
            }
            w[i] <== word;
        } else {
            schedule0[i-16] = ShaSigma(7,18,3,1);
            schedule1[i-16] = ShaSigma(17,19,10,1);
            for (var j = 0; j < 32; j++) {
                schedule0[i-16].bits[j] <== wb[i-15][j];
                schedule1[i-16].bits[j] <== wb[i-2][j];
            }
            schedule[i-16] = ShaWordAdd(4,34);
            schedule[i-16].words[0] <== schedule0[i-16].value;
            schedule[i-16].words[1] <== schedule1[i-16].value;
            schedule[i-16].words[2] <== w[i-7];
            schedule[i-16].words[3] <== w[i-16];
            w[i] <== schedule[i-16].value;
            for (var j = 0; j < 32; j++) wb[i][j] <== schedule[i-16].bits[j];
        }
    }
    signal v[65][8];
    signal bits[65][8][32];
    component start[8];
    for (var j = 0; j < 8; j++) {
        v[0][j] <== initial[j];
        start[j] = Unsigned(32);
        start[j].value <== initial[j];
        for (var b = 0; b < 32; b++) bits[0][j][b] <== start[j].bits[b];
    }
    component sigmaA[64];
    component sigmaE[64];
    component addA[64];
    component addE[64];
    signal choose[64][32];
    signal xorAB[64][32];
    signal majority[64][32];
    for (var i = 0; i < 64; i++) {
        sigmaA[i] = ShaSigma(2,13,22,0);
        sigmaE[i] = ShaSigma(6,11,25,0);
        var ch = 0;
        var maj = 0;
        for (var b = 0; b < 32; b++) {
            var a = bits[i][0][b];
            var bb = bits[i][1][b];
            var c = bits[i][2][b];
            var e = bits[i][4][b];
            var f = bits[i][5][b];
            var g = bits[i][6][b];
            sigmaA[i].bits[b] <== a;
            sigmaE[i].bits[b] <== e;
            choose[i][b] <== g+e*(f-g);
            xorAB[i][b] <== a+bb-2*a*bb;
            majority[i][b] <== bb+xorAB[i][b]*(c-bb);
            ch += choose[i][b] * (1 << b);
            maj += majority[i][b] * (1 << b);
        }
        var t1 = v[i][7] + sigmaE[i].value + ch + k[i] + w[i];
        addA[i] = ShaWordAdd(3,35);
        addA[i].words[0] <== t1;
        addA[i].words[1] <== sigmaA[i].value;
        addA[i].words[2] <== maj;
        addE[i] = ShaWordAdd(2,35);
        addE[i].words[0] <== t1;
        addE[i].words[1] <== v[i][3];
        for (var j = 0; j < 8; j++) {
            if (j == 0) {
                v[i+1][j] <== addA[i].value;
                for (var b = 0; b < 32; b++) bits[i+1][j][b] <== addA[i].bits[b];
            } else if (j == 4) {
                v[i+1][j] <== addE[i].value;
                for (var b = 0; b < 32; b++) bits[i+1][j][b] <== addE[i].bits[b];
            } else {
                v[i+1][j] <== v[i][j-1];
                for (var b = 0; b < 32; b++) bits[i+1][j][b] <== bits[i][j-1][b];
            }
        }
    }
    component accumulated[8];
    for (var i = 0; i < 8; i++) {
        accumulated[i] = ShaWordAdd(2,33);
        accumulated[i].words[0] <== initial[i];
        accumulated[i].words[1] <== v[64][i];
        state[i] <== accumulated[i].value;
    }
}

template Sha256Bytes(length) {
    signal input data[length];
    signal output digest[32];
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
    component words[8];
    for (var i = 0; i < 8; i++) {
        words[i] = Unsigned(32);
        words[i].value <== rounds[blocks-1].state[i];
        for (var j = 0; j < 4; j++) {
            var byte = 0;
            for (var b = 0; b < 8; b++) byte += words[i].bits[(3-j)*8+b] * (1 << b);
            digest[i*4+j] <== byte;
        }
    }
}

template Hash256Bytes(length) {
    signal input data[length];
    signal output digest[32];
    component first = Sha256Bytes(length);
    component second = Sha256Bytes(32);
    for (var i = 0; i < length; i++) first.data[i] <== data[i];
    for (var i = 0; i < 32; i++) second.data[i] <== first.digest[i];
    for (var i = 0; i < 32; i++) digest[i] <== second.digest[i];
}
