pragma circom 2.2.3;

include "transfer_commitment.circom";

component main {public [digestHigh, digestLow]} = TransferCommitment(1, 2, 192);
