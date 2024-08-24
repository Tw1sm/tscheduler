from tscheduler.logger import OBJ_EXTRA_FMT, ColorScheme, console

__version__ = '0.1.0'

def banner():
    console.print(f'''
    TSCHEDULER
    ''')

    console.print(f'                             v[cyan]{__version__}[/]\n')