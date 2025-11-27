class Response:
    def __init__(self, status_code: int = 200, json_data=None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text

    def json(self):
        return self._json_data


class Session:
    def post(self, *args, **kwargs):
        return Response()


def get(*args, **kwargs):
    return Response()


def post(*args, **kwargs):
    return Response()

