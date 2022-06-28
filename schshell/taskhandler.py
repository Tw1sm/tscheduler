from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SessionError
from impacket import uuid
from schshell import OBJ_EXTRA_FMT, ColorScheme, console
from rich import print_json
import xmltodict
import logging
import json


class TaskHandler:
    '''
    Use Impacket's MS-TSCH implementation to remotely manage scheduled tasks
    '''
    def __init__(self, path=None, username='', password='', domain='', target='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.__path = path
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = target
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__dce = None
        self.__output_file = 'tasks.json'

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
            logging.debug(f'Identified task {ColorScheme.task}{name}[/] in {ColorScheme.folder}{folder.path}', extra=OBJ_EXTRA_FMT)
        
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
        root = TaskFolder('ROOT', TaskFolder.TASK_ROOT)
        self._rpc_enum_path(root)
        with open(self.__output_file, 'w') as f:
            f.write(root.toJSON())
        logging.info(f'Task names and folders dumped to ./{self.__output_file}')

    
    def enum_task(self, xml=False):
        '''
        Enumerate a task's state, running instances and jump configs to JSON or XML
        '''
        self._get_task_state()
        self._get_task_instances()
        resp = tsch.hSchRpcRetrieveTask(self.__dce, self.__path)

        print()
        if xml:
            print(resp['pXml'])
        else:
            xparsed = xmltodict.parse(resp['pXml'][:-1])
            print_json(json.dumps(xparsed))
        

    def run_task(self):
        '''
        Queue a task for execution
        '''
        try:
            resp = tsch.hSchRpcRun(self.__dce, self.__path)
            logging.info(f'Task started: {self.__path}')
        except tsch.DCERPCSessionError as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid task path')
            elif '0x80041326' in str(e):
                logging.error(f'Task failed to start with error code 0x80041326 - is task enabled?')
            else:
                logging.error(str(e))
            exit()

    
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
        except tsch.DCERPCSessionError as e:
            if 'ERROR_FILE_NOT_FOUND' in str(e):
                logging.error(f'ERROR_FILE_NOT_FOUND - Invalid folder path')
            else:
                logging.error(str(e))
            exit()

    
    def _get_task_instances(self):
        try:
            resp = tsch.hSchRpcEnumInstances(self.__dce, self.__path)
        except tsch.DCERPCSessionError as e:
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
        except tsch.DCERPCSessionError as e:
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
        try:
            resp = tsch.hSchRpcEnableTask(self.__dce, self.__path, enable)
            if resp['ErrorCode'] != 0:
                logging.critical(f'RPC call returned error code {resp["ErrorCode"]} - change may have failed')
        except tsch.DCERPCSessionError as e:
            if 'E_ACCESSDENIED' in str(e):
                logging.error('Error enabling task - E_ACCESSDENIED')
                return
            else:
                logging.error(str(e))
                return

        # check task enabled/disabled after change
        self._get_task_state()


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



    