pragma circom 2.2.3;

include "../../groth16/circuits/sha256_bytes.circom";

template CommittedSlots(count, firstIndex) {
    signal input slots[count][12];
    signal output total;
    signal index[count];
    signal quantity[count];
    signal inverse[count];
    component ordered[count];
    var sum = 0;
    for (var i = 0; i < count; i++) {
        var decodedIndex = 0;
        var decodedQuantity = 0;
        for (var j = 0; j < 4; j++) decodedIndex += slots[i][j] * (1 << (8*j));
        for (var j = 0; j < 8; j++) decodedQuantity += slots[i][4+j] * (1 << (8*j));
        index[i] <== decodedIndex;
        quantity[i] <== decodedQuantity;
        inverse[i] <-- quantity[i] == 0 ? 0 : 1 / quantity[i];
        quantity[i] * inverse[i] === 1;
        ordered[i] = Unsigned(32);
        if (i == 0) ordered[i].value <== index[i] - firstIndex;
        else ordered[i].value <== index[i] - index[i-1] - 1;
        sum += quantity[i];
    }
    total <== sum;
}

// The prefix contains the asset and verifier key identities. The full
// relation must pin both and match the slots against the transaction.
template TransferCommitment(inputCount, outputCount, preimageLength) {
    assert(inputCount > 0 && inputCount <= 256);
    assert(outputCount > 0 && outputCount <= 256);
    assert(preimageLength >= 157);
    signal input prefix[64];
    signal input preimage[preimageLength];
    signal input inputSlots[inputCount][12];
    signal input outputSlots[outputCount][12];
    signal input digestHigh;
    signal input digestLow;

    var domain[21] = [66,83,86,47,67,67,84,80,47,116,114,97,110,115,102,101,114,47,118,49,0];
    var inputOffset = 21 + 96;
    var outputOffset = inputOffset + 2 + 12*inputCount;
    component commitment = Hash256Bytes(outputOffset + 2 + 12*outputCount);
    for (var i = 0; i < 21; i++) commitment.data[i] <== domain[i];
    for (var i = 0; i < 64; i++) commitment.data[21+i] <== prefix[i];
    component txDigest = Hash256Bytes(preimageLength);
    for (var i = 0; i < preimageLength; i++) txDigest.data[i] <== preimage[i];
    preimage[preimageLength-4] === 65;
    for (var i = 1; i <= 3; i++) preimage[preimageLength-i] === 0;
    for (var i = 0; i < 32; i++) commitment.data[21+64+i] <== txDigest.digest[i];
    commitment.data[inputOffset] <== inputCount % 256;
    commitment.data[inputOffset+1] <== inputCount \ 256;
    commitment.data[outputOffset] <== outputCount % 256;
    commitment.data[outputOffset+1] <== outputCount \ 256;

    component incoming = CommittedSlots(inputCount, 1);
    component outgoing = CommittedSlots(outputCount, 0);
    for (var i = 0; i < inputCount; i++) {
        for (var j = 0; j < 12; j++) {
            commitment.data[inputOffset+2+12*i+j] <== inputSlots[i][j];
            incoming.slots[i][j] <== inputSlots[i][j];
        }
    }
    for (var i = 0; i < outputCount; i++) {
        for (var j = 0; j < 12; j++) {
            commitment.data[outputOffset+2+12*i+j] <== outputSlots[i][j];
            outgoing.slots[i][j] <== outputSlots[i][j];
        }
    }
    component total = Unsigned(64);
    total.value <== incoming.total;
    incoming.total === outgoing.total;

    var high = 0;
    var low = 0;
    for (var i = 0; i < 16; i++) {
        high = 256 * high + commitment.digest[i];
        low = 256 * low + commitment.digest[16+i];
    }
    digestHigh === high;
    digestLow === low;
}
