class _MemoryInfo:
    def __init__(self, rss: int = 0):
        self.rss = rss


class Process:
    def memory_info(self) -> _MemoryInfo:
        return _MemoryInfo(10 * 1024 * 1024)

