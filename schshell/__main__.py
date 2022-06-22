import typer
import logging
from impacket import version
from impacket.examples.utils import parse_target
from schshell import __version__, console
from schshell.taskhandler import TaskHandler

app = typer.Typer(add_completion=False)

@app.command(no_args_is_help=True)
def main(
    target: str = typer.Argument(..., help='[[domain/]username[:password]@]<targetName or address>'),
    path: str = typer.Option(None, '-path', metavar='PATH', help='Target task or folder path [example: \Microsoft]'),
    enum_all: bool = typer.Option(False, '-enum-all', help='Enumerate scheduled tasks on the target'),
    enum_folder: bool = typer.Option(False, '-enum-folder', help='Enumerate a task folder'),
    enum_task: bool = typer.Option(False, '-enum-task', help='Enumerate a specific scheduled task'),
    run: bool = typer.Option(False, '-run', help='Execute a scheduled task'),
    enable: bool = typer.Option(False, '-enable', help='Enable a disabled task'),
    disable: bool = typer.Option(False, '-disable', help='Disable an enabled task'),
    xml: bool = typer.Option(False, '-xml', help='Return enumerated task as XML instead of JSON'),
    hashes: str = typer.Option(None, '-hashes', metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH'),
    no_pass: bool = typer.Option(False, '-no-pass', help='Don\'t ask for password (useful for -k)'),
    kerberos: bool = typer.Option(False, '-k', help='Use Kerberos authentication. Grabs credentials from ccache file '
                                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                                        'cannot be found, it will use the ones specified in the command '
                                        'line'),
    aesKey: str = typer.Option(None, '-aesKey', help='AES key to use for Kerberos Authentication (128 or 256 bits)'),
    domain_controller: str = typer.Option('', '-dc-ip', help='Domain controller IP or hostname to query'),
    debug: bool = typer.Option(False, '-debug', help='Turn DEBUG output ON')):
    '''
    Tool for remotely managing Scheduled Tasks
    '''

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if path is None and (enum_task or enum_folder or run or enable or disable):
        logging.critical('-path argument is required for one of your other flags')
        print()
        exit()

    if not enum_all and not enum_folder and not enum_task and not run and not enable \
        and not disable:
        logging.critical('No action flag provided. See --help')
        print()
        exit()

    banner()
    logging.debug(version.BANNER[:-1])

    domain, username, password, host = parse_target(target)

    if password == '' and username != '' and hashes is None and no_pass is False and aesKey is None:
        from getpass import getpass
        password = getpass('Password:')

    lm_hash = ""
    nt_hash = ""
    if hashes is not None:
        if ":" in hashes:
            lm_hash = hashes.split(":")[0]
            nt_hash = hashes.split(":")[1]
        else:
            nt_hash = hashes
    
    if domain_controller == "":
        domain_controller = domain

    if aesKey is not None:
        kerberos = True    

    task_handler = TaskHandler(path, username, password, domain, host, hashes, aesKey, kerberos, domain_controller)
    
    if enum_all:
        task_handler.enum_all_tasks()

    if enum_task:
        task_handler.enum_task(xml)

    if enum_folder:
        task_handler.enum_folder()

    if run:
        task_handler.run_task()

    if enable:
        task_handler.enable_task(enable=True)

    if disable:
        task_handler.enable_task(enable=False)

    task_handler.disconnect()


def banner():
    console.print(f'''
    
 _______  _______  __   __ [yellow] _______  __   __  _______  ___      ___     [/]
|       ||       ||  | |  |[yellow]|       ||  | |  ||       ||   |    |   |    [/]
|  _____||       ||  |_|  |[yellow]|  _____||  |_|  ||    ___||   |    |   |    [/]
| |_____ |       ||       |[yellow]| |_____ |       ||   |___ |   |    |   |    [/]
|_____  ||      _||       |[yellow]|_____  ||       ||    ___||   |___ |   |___ [/]
 _____| ||     |_ |   _   |[yellow] _____| ||   _   ||   |___ |       ||       |[/]
|_______||_______||__| |__|[yellow]|_______||__| |__||_______||_______||_______|[/]
    ''')

    console.print(f'                             v{__version__}\n', highlight=False)

if __name__ == "__main__":
    app(prog_name="schshell")