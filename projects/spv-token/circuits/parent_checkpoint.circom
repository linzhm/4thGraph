pragma circom 2.2.3;

include "parent_checkpoint_relation.circom";

component main {public [digestHigh, digestLow]} = ParentCheckpoint(332, 256, 307, 2, 0);
