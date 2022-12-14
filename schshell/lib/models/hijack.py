from enum import Enum

class Hijack(Enum):
    FODCleanupTask = 'FODCleanupTask'
    ScanForUpdates = 'ScanForUpdates'
    NGEN64 = 'NGEN64'
    Device = 'Device'


class DLLHijack:
    
    def __init__(self, task, path, reference=None):
        self.task = task
        self.path = path
        self.reference = reference
