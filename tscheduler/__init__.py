from tscheduler.logger import OBJ_EXTRA_FMT, logging, ColorScheme, console

__version__ = '0.1.0'

def banner():
    logging.info(f'tschduler [cyan]v{__version__}[/]', extra=OBJ_EXTRA_FMT)