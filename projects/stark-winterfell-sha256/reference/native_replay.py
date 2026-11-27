"""Open the native engines used by the versioned SHA-256 replays."""

from importlib.metadata import PackageNotFoundError
import os

from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata


def native_engines():
    try:
        chain_gang = chain_metadata()
    except PackageNotFoundError as error:
        raise ValueError("Native replay requires tx-engine from tools/requirements-chronicle.txt.") from error
    if chain_gang["commit"] != CONTEXT_PIN:
        raise ValueError(
            f"native replay requires chain-gang at {CONTEXT_PIN}, found {chain_gang['commit']!r}. "
            "Install from tools/requirements-chronicle.txt."
        )
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    return node, {"bsv_node_version": node.version, "chain_gang": chain_gang}
