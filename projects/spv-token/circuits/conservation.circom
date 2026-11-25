pragma circom 2.2.3;

include "statement_digest.circom";

template Conservation() {
    signal input payload[560];
    signal input digestHigh;
    signal input digestLow;
    var domain[25] = [66,83,86,47,67,67,84,80,47,99,111,110,115,101,114,118,97,116,105,111,110,47,118,49,0];
    component digest = StatementDigest(domain, 25, 560);
    for (var i = 0; i < 560; i++) digest.payload[i] <== payload[i];
    digest.digestHigh <== digestHigh;
    digest.digestLow <== digestLow;

    signal quantity[4];
    signal sats[4];
    signal quantityInverse[4];
    signal satsInverse[4];
    for (var i = 0; i < 4; i++) {
        var start = 104 + 114 * i;
        var q = 0;
        var s = 0;
        for (var j = 0; j < 8; j++) {
            q += payload[start+40+j] * (1 << (8*j));
            s += payload[start+j] * (1 << (8*j));
        }
        quantity[i] <== q;
        sats[i] <== s;
        quantityInverse[i] <-- q == 0 ? 0 : 1/q;
        satsInverse[i] <-- s == 0 ? 0 : 1/s;
        quantity[i] * quantityInverse[i] === 1;
        sats[i] * satsInverse[i] === 1;
        payload[start+81] === 0;
        (payload[start+48] - 2) * (payload[start+48] - 3) === 0;
        if (i > 0) {
            for (var j = 8; j < 40; j++) payload[start+j] === payload[104+j];
            for (var j = 82; j < 114; j++) payload[start+j] === payload[104+j];
        }
    }
    component inputTotal = Unsigned(64);
    inputTotal.value <== quantity[0] + quantity[1];
    quantity[0] + quantity[1] === quantity[2] + quantity[3];
    sats[0] + sats[1] === sats[2] + sats[3];
}

component main {public [digestHigh, digestLow]} = Conservation();
