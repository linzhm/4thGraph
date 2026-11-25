from shared.sdk.python.client import Client


def create_client(**config):
    """Create a local wots-plus wallet client."""
    return Client("wots-plus", **config)
