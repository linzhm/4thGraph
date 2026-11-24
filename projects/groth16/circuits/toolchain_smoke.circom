pragma circom 2.2.3;

template ToolchainSmoke() {
    signal input outputValue;
    signal input offset;
    signal input a;
    signal input b;
    signal product;
    product <== a * b;
    outputValue === product + offset;
}

component main {public [outputValue, offset]} = ToolchainSmoke();
