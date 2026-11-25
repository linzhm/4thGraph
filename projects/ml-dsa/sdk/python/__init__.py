from shared.sdk.python.client import Client


def create_client(**config):
    """Create a local ml-dsa wallet client."""
    return Client("ml-dsa", **config)
