from shared.sdk.python.client import Client


def create_client(**config):
    """Create a local p2pkh-sm2 wallet client."""
    return Client("p2pkh-sm2", **config)
