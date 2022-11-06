from schshell.lib.models.principal import Principal
from schshell.lib.models.hijack import Hijack, DLLHijack


DLL_HIJACKS = {
    'FODCleanupTask': DLLHijack(
        task='\\Microsoft\\Windows\\HelloFace\\FODCleanupTask',
        path='C:\\Windows\\System32\\WinBioPlugIns\\winbio.dll',
        reference='C:\\Windows\\System32\\winbio.dll'
    ),
    'ScanForUpdates': DLLHijack(
        task='\\Microsoft\\Windows\\InstallService\\ScanForUpdates',
        path='C:\\Windows\\System32\\windowscoredeviceinfo.dll',
        reference=None
    )
}
