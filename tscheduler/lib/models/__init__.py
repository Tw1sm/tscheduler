from tscheduler.lib.models.principal import Principal
from tscheduler.lib.models.hijack import Hijack, DLLHijack


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
    ),
    'NGEN64': DLLHijack(
        task='\\Microsoft\\Windows\\.NET Framework\\.NET Framework NGEN v4.0.30319 64',
        path='C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscoree.dll',
        reference='C:\\Windows\\System32\\mscoree.dll'
    ),
    'Device': DLLHijack(
        task='\\Microsoft\\Windows\Device Information\\Device',
        path='C:\\Windows\\System32\\minuser.dll',
        reference=None
    )
}
