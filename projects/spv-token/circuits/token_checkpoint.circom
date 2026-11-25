pragma circom 2.2.3;

include "parent_checkpoint_relation.circom";

component main {public [digestHigh, digestLow]} = ParentCheckpoint(3433, 1856, 1871, 1, 1);
