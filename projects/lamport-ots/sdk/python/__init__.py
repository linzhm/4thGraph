from shared.sdk.python.client import Client


def create_client(**config):
    """Create a local lamport-ots wallet client."""
    return Client("lamport-ots", **config)
