"""Replay both BLS12-381 fixed-statement locks with the same key and proof."""
from argparse import ArgumentParser
import json
import os
from pathlib import Path
from time import perf_counter
from statistics import median

from fourthgraph.verification.bls12381.verifier import ScriptVerifier
from fourthgraph.replay.groth16_bn254 import fund, sign_spend, verify_spend
from fourthgraph.workflow.protocol import FLAG, authorize
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.benchmark.admission import submit_and_mine
from fourthgraph.benchmark.validation import Node
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.transaction import Input, Output, Transaction

parser = ArgumentParser(description=__doc__)
parser.add_argument("fixture", type=Path)
parser.add_argument("scripts", type=Path)
args = parser.parse_args()
root = args.scripts
fixture = args.fixture
data = json.loads(fixture.read_text())
enc = lambda part: json.dumps(part).encode()
signals = tuple(map(int, data["wrap"]["public"]))
other = tuple(map(int, data["other"]["public"]))
verifier = ScriptVerifier(enc(data["verification_key"]))
keys = TestKeys()
owner = keys.public["operator"]
read_hex = lambda file: bytes.fromhex((root/file).read_text())
cases = {
    "nchain": (authorize(owner)+read_hex("nchain-fixed-lock.hex"),
               read_hex("nchain-fixed-wrap.hex"),read_hex("nchain-fixed-other.hex")),
    "4thgraph": (verifier.compile(signals,owner),
                 verifier.witness(signals, enc(data["wrap"]["proof"])),
                 verifier.witness(other, enc(data["other"]["proof"]))),
}
node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
report = {}
for label,(lock,witness,different) in cases.items():
    native, bootstrap = fund(node,2)
    deploy = Transaction((Input(bootstrap.txid_wire(),0),),(Output(2_000_000,lock),),version=2)
    deploy = native.unlock(deploy,0,bootstrap,FLAG,None)
    deployed = submit_and_mine(node,deploy)
    assert deployed["mined"], deployed
    tx = Transaction((Input(deploy.txid_wire(),0),),(Output(1_900_000,native.output.script),),version=2)
    good = sign_spend(tx,deploy,witness,keys)
    context = dict(spend_height=deployed["height"]+1,utxo_heights=(deployed["height"],),activation_height=activation)
    node_samples, chain_samples = [], []
    for _ in range(7):
        t=perf_counter()
        assert node.verdicts(good,(deploy,),timeout_us=10000,**context)==[True]
        node_samples.append(1000*(perf_counter()-t))
        t=perf_counter()
        validate_at_heights(good,(deploy,),**context)
        chain_samples.append(1000*(perf_counter()-t))
    wrong = verify_spend(node,activation,sign_spend(tx,deploy,different,keys),deploy,deployed["height"],expected=False)
    valid = verify_spend(node,activation,good,deploy,deployed["height"],expected=True)
    report[label] = dict(lock_bytes=len(lock),witness_prefix_bytes=len(witness),
        unlock_bytes=len(good.inputs[0].script),deployment_bytes=deployed["bytes"],spend_bytes=len(good.serialize()),
        node_rpc_median_ms=median(node_samples),chain_gang_median_ms=median(chain_samples),
        valid_admission=valid["admission"],wrong_statement_admission=wrong["admission"])
print(json.dumps(report,indent=2))
(root/"same-proof-replay.json").write_text(json.dumps(report,indent=2)+"\n")
