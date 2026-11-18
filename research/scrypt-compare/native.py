"""Compare complete input validation locally using the same public signing vector."""
import json
import os
import time
import statistics
import struct
import base64
import urllib.request
from pathlib import Path

tmp = Path(os.environ["RUNNER_TEMP"])
fixture = json.loads(Path("template/spend-all.json").read_text())
auth = base64.b64encode(Path(os.environ["REGTEST_COOKIE"]).read_bytes().strip()).decode()
def compact(n):
    if n < 253: return bytes([n])
    if n < 65536: return b"\xfd" + struct.pack("<H",n)
    return b"\xfe" + struct.pack("<I",n)

unsigned = bytes.fromhex(fixture["unsigned_tx_hex"])
assert unsigned[4] == 1 and unsigned[41] == 0
names = ["pels", "scrypt"]
if (tmp / "eight-lock.bin").exists():
    names.append("eight")
for name in names:
    lock = (tmp / (name + "-lock.bin")).read_bytes()
    witness = (tmp / (name + "-unlock.bin")).read_bytes()
    tx = unsigned[:41] + compact(len(witness)) + witness + unsigned[42:]
    flags = sum(1 << b for b in (1,2,3,16,18,19,20,21))
    inp = dict(tx=tx.hex(), n=0, flags=flags, reportflags=True,
               txo=dict(lock=lock.hex(), value=fixture["previous_amount_sats"], height=3))
    body = json.dumps(dict(jsonrpc="1.0", id=1, method="verifyscript", params=[[inp],False,15000])).encode()
    req = urllib.request.Request("http://127.0.0.1:18443", data=body,
                                 headers={"Authorization":"Basic " + auth, "Content-Type":"application/json"})
    elapsed = []
    for run in range(6):
        start = time.perf_counter_ns()
        with urllib.request.urlopen(req,timeout=30) as response:
            data = json.load(response)
        total = (time.perf_counter_ns()-start)/1e6
        if data.get("error") or data["result"][0]["result"] != "ok":
            raise ValueError(str(data)[:1000])
        if data["result"][0]["flags"] & flags != flags:
            raise ValueError("missing requested flags")
        if run: elapsed.append(round(total,3))
    print("NATIVE_RESULT", name, "RPC_ms", elapsed, "median_ms",statistics.median(elapsed),flush=True)
