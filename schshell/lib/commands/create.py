from operator import imod
from xmlrpc.client import SYSTEM_ERROR
import typer
import logging
from schshell.lib.taskhandler import TaskHandler
from schshell.lib.models import Principal
from schshell import banner
from impacket.examples.utils import parse_target


app = typer.Typer()
COMMAND_NAME = 'create'
HELP = 'Create and register a new scheduled task'


@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    target:             str             = typer.Argument(..., help='[domain/]username[:password]@]<targetName or address>'),
    task:               str             = typer.Option(..., '-t', '--task', help='Full path of the task [Example: \Microsoft\Windows\MyTask]'),
    command:            str             = typer.Option(None, '-c', '--command', help='Command the new task will execute'),
    args:               str             = typer.Option(None, '-a', '--args', help='Arguments the task will pass to the command'),
    principal:          Principal       = typer.Option('SYSTEM', '-p', '--principal', case_sensitive=False, help='Principal the task runs as (User for logged-in user) (useful for --session when starting task)'),
    xml:                typer.FileText  = typer.Option(None, '--xml', help='Path to custom task XML file'),
    hashes:             str             = typer.Option(None, '--hashes', metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH'),
    no_pass:            bool            = typer.Option(False, '--no-pass', help='Don\'t ask for password (useful for -k)'),
    kerberos:           bool            = typer.Option(False, '-k', '--kerberos', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line'),
    aesKey:             str             = typer.Option(None, '--aesKey', help='AES key to use for Kerberos Authentication (128 or 256 bits)'),
    domain_controller:  str             = typer.Option('', '--dc-ip', help='Domain controller IP or hostname to query'),
    debug:              bool            = typer.Option(False, '--debug', help='Turn DEBUG output ON')):

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    banner()

    # Arg guardrails
    if command is None and xml is None:
        logging.warning('Either a command or custom task XML must be supplied')
        exit()

    if command is not None and xml is not None:
        logging.warning('A command cannot be specified when custom task XML is used')
        exit()

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
    task_handler.create_task(principal, command, args, xml)
    task_handler.disconnect()