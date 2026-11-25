pragma circom 2.2.3;

template Unsigned(width) {
    signal input value;
    signal output bits[width];
    var sum = 0;
    for (var i = 0; i < width; i++) {
        bits[i] <-- (value >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        sum += bits[i] * (1 << i);
    }
    value === sum;
}

// Inputs are already range constrained to 144 bits by MimoRelation.
template Less144() {
    signal input left;
    signal input right;
    signal output result;
    component adjusted = Unsigned(145);
    adjusted.value <== left + (1 << 144) - right;
    result <== 1 - adjusted.bits[144];
}

template EqualField() {
    signal input left;
    signal input right;
    signal output result;
    signal inverse;
    signal difference <== left - right;
    inverse <-- difference != 0 ? 1 / difference : 0;
    result <== 1 - difference * inverse;
    difference * result === 0;
}

template MimoRelation(maxInputs, maxOutputs) {
    assert(maxInputs > 0);
    assert(maxOutputs > 0);
    // This bound keeps every possible component sum well below the scalar field.
    assert(maxInputs < (1 << 128));
    assert(maxOutputs < (1 << 128));

    signal input inputTotal;
    signal input outputTotal;
    signal input inputAmount[maxInputs];
    signal input inputHigh[maxInputs];
    signal input inputLow[maxInputs];
    signal input outputAmount[maxOutputs];

    component incoming[maxInputs];
    component high[maxInputs];
    component low[maxInputs];
    component inputZero[maxInputs];
    component lessHigh[maxInputs - 1];
    component equalHigh[maxInputs - 1];
    component lessLow[maxInputs - 1];
    signal ordered[maxInputs - 1];
    signal active[maxInputs];
    var inSum = 0;
    for (var i = 0; i < maxInputs; i++) {
        incoming[i] = Unsigned(64);
        high[i] = Unsigned(144);
        low[i] = Unsigned(144);
        inputZero[i] = EqualField();
        incoming[i].value <== inputAmount[i];
        high[i].value <== inputHigh[i];
        low[i].value <== inputLow[i];
        inputZero[i].left <== inputAmount[i];
        inputZero[i].right <== 0;
        active[i] <== 1 - inputZero[i].result;
        (1 - active[i]) * inputHigh[i] === 0;
        (1 - active[i]) * inputLow[i] === 0;
        inSum += inputAmount[i];

        if (i > 0) {
            (1 - active[i - 1]) * active[i] === 0;
            lessHigh[i - 1] = Less144();
            equalHigh[i - 1] = EqualField();
            lessLow[i - 1] = Less144();
            lessHigh[i - 1].left <== inputHigh[i - 1];
            lessHigh[i - 1].right <== inputHigh[i];
            equalHigh[i - 1].left <== inputHigh[i - 1];
            equalHigh[i - 1].right <== inputHigh[i];
            lessLow[i - 1].left <== inputLow[i - 1];
            lessLow[i - 1].right <== inputLow[i];
            ordered[i - 1] <== lessHigh[i - 1].result + equalHigh[i - 1].result * lessLow[i - 1].result;
            active[i] * (1 - ordered[i - 1]) === 0;
        }
    }
    active[0] === 1;

    component outgoing[maxOutputs];
    var outSum = 0;
    for (var j = 0; j < maxOutputs; j++) {
        outgoing[j] = Unsigned(64);
        outgoing[j].value <== outputAmount[j];
        outSum += outputAmount[j];
    }
    component supply = Unsigned(64);
    supply.value <== inputTotal;
    inputTotal === inSum;
    outputTotal === outSum;
    inputTotal === outputTotal;
}
