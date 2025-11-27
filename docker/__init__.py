class _ImageCollection:
    def get(self, image_name: str):
        return type("Image", (), {"attrs": {"Config": {}}})()


class _DockerClient:
    def __init__(self):
        self.images = _ImageCollection()


def from_env():
    """Return a minimal docker client stub used for unit tests."""
    return _DockerClient()

