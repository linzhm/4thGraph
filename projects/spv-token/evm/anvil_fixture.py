"""Foundry helpers for local integration tests with disposable chain state."""

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import socket
import subprocess
import time

from mint_events import DepositPosition
from evm.reserve_rpc import DEPOSIT_TOPIC, DepositEvidenceError, EvmJsonRpc

ROOT = Path(__file__).resolve().parent
CHAIN_ID = 31337
RESERVE_DOMAIN = 7
BSV_NETWORK = 1
HAS_FOUNDRY = all(shutil.which(tool) for tool in ("forge", "cast", "anvil"))


def _command(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=50, check=True).stdout.strip()


@dataclass(frozen=True)
class LocalEvm:
    rpc: EvmJsonRpc
    url: str

    def deploy(self, contract, admin, *parameters):
        args = ("--constructor-args", *parameters) if parameters else ()
        result = _command("forge", "create", contract, "--root", str(ROOT), "--rpc-url", self.url,
                          "--from", admin, "--unlocked", "--broadcast", "--json", *args)
        return json.loads(result)["deployedTo"]

    def send(self, contract, function, *args, sender):
        result = _command("cast", "send", "--rpc-url", self.url, "--from", sender,
                          "--unlocked", "--json", contract, function, *args)
        receipt = json.loads(result)
        if receipt["status"] != "0x1":
            raise AssertionError("local EVM transaction reverted")
        return receipt

    def call(self, contract, function, *args):
        return _command("cast", "call", "--rpc-url", self.url, contract, function, *args).split()[0]

    def accounts(self):
        return json.loads(_command("cast", "rpc", "--rpc-url", self.url, "eth_accounts"))

    def mine_finality(self):
        _command("cast", "rpc", "--rpc-url", self.url, "anvil_mine", "0x46")


def address_for_key(key):
    return _command("cast", "wallet", "address", "--private-key", key)


def sign_digest_for_test(key, digest):
    return _command("cast", "wallet", "sign", "--no-hash", digest, "--private-key", key)


def deposit_position(receipt, vault):
    ordinal, = (
        i for i, log in enumerate(receipt["logs"])
        if log["topics"] and log["topics"][0] == "0x" + DEPOSIT_TOPIC.hex()
    )
    return DepositPosition(CHAIN_ID, RESERVE_DOMAIN, bytes.fromhex(vault[2:]),
                           bytes.fromhex(receipt["transactionHash"][2:]), ordinal)


@contextmanager
def start_anvil():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    node = subprocess.Popen(
        ["anvil", "--host", "127.0.0.1", "--port", str(port), "--chain-id", str(CHAIN_ID), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        rpc = EvmJsonRpc(url)
        deadline = time.monotonic() + 5
        while True:
            try:
                if rpc("eth_chainId") != hex(CHAIN_ID):
                    raise AssertionError("local EVM has unexpected chain ID")
                break
            except DepositEvidenceError:
                if node.poll() is not None or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        yield LocalEvm(rpc, url)
    finally:
        if node.poll() is None:
            node.terminate()
            try:
                node.wait(timeout=5)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait()
