pragma circom 2.2.3;

include "statement_digest.circom";

template FreezeTransition() {
    signal input payload[300];
    signal input digestHigh;
    signal input digestLow;
    var domain[30] = [66,83,86,47,67,67,84,80,47,102,114,101,101,122,101,45,116,114,97,110,115,105,116,105,111,110,47,118,49,0];
    component digest = StatementDigest(domain, 30, 300);
    for (var i = 0; i < 300; i++) digest.payload[i] <== payload[i];
    digest.digestHigh <== digestHigh;
    digest.digestLow <== digestLow;

    var prior = 72;
    var successor = prior + 114;
    for (var i = 0; i < 114; i++) {
        if (i != 81) payload[prior+i] === payload[successor+i];
    }
    payload[prior+81] * (payload[prior+81] - 1) === 0;
    payload[prior+81] + payload[successor+81] === 1;
    (payload[prior+48] - 2) * (payload[prior+48] - 3) === 0;
    var quantity = 0;
    for (var i = 0; i < 8; i++) quantity += payload[prior+40+i] * (1 << (8*i));
    signal inverse <-- quantity == 0 ? 0 : 1 / quantity;
    inverse * quantity === 1;
}

component main {public [digestHigh, digestLow]} = FreezeTransition();
