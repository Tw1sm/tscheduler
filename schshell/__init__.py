from schshell.logger import OBJ_EXTRA_FMT, ColorScheme, console

__version__ = '0.1.0'

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

    console.print(f'                             v[cyan]{__version__}[/]\n')