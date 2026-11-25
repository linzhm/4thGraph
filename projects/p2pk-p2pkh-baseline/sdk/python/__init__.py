from shared.sdk.python.client import Client


def create_client(**config):
    """Create a local p2pk-p2pkh-baseline wallet client."""
    return Client("p2pk-p2pkh-baseline", **config)
