import typer
import logging
from tscheduler.lib.taskhandler import TaskHandler
from tscheduler import banner
from impacket.examples.utils import parse_target


app = typer.Typer()
COMMAND_NAME = 'enum'
HELP = 'Enumerate scheduled tasks and/or folders'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    target:             str     = typer.Argument(..., help='\[\[domain/]username[:password]@]<targetName or address>'),
    task:               str     = typer.Option(None, '-t', '--task', help='Full path of the task or folder [Example: \Microsoft\Windows\MyTask]', rich_help_panel="Task Options"),
    folder:             bool    = typer.Option(False, '--folder', help='The specified task path is a folder and not a task', rich_help_panel="Task Options"),
    all:                bool    = typer.Option(False, '--all', help='Enumerate all tasks and folders on the target', rich_help_panel="Task Options"),
    json:               bool    = typer.Option(False, '--json', help='Return the task configs as JSON instead of XML', rich_help_panel="Output Options"),
    hashes:             str     = typer.Option(None, '--hashes', metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH', rich_help_panel="Authentication Options"),
    no_pass:            bool    = typer.Option(False, '--no-pass', help='Don\'t ask for password (useful for -k)', rich_help_panel="Authentication Options"),
    kerberos:           bool    = typer.Option(False, '-k', '--kerberos', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line', rich_help_panel="Authentication Options"),
    aesKey:             str     = typer.Option(None, '--aesKey', help='AES key to use for Kerberos Authentication (128 or 256 bits)', rich_help_panel="Authentication Options"),
    domain_controller:  str     = typer.Option('', '--dc-ip', help='Domain controller IP or hostname to query', rich_help_panel="Authentication Options"),
    debug:              bool    = typer.Option(False, '--debug', help='Turn DEBUG output ON'),
    quiet:              bool            = typer.Option(False, '--quiet', help='Hide banner')):

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if not quiet:
        banner()

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

    task_handler = TaskHandler(task, username, password, domain, host, lm_hash, nt_hash, aesKey, kerberos, domain_controller)
    
    if all:
        task_handler.enum_all_tasks()
    elif folder:
        task_handler.enum_folder()
    else:
        task_handler.enum_task(not json)


    task_handler.disconnect()