import logging
from rich.logging import RichHandler
from rich.console import Console

# can also be set to 'truecolor'
console = Console(color_system='256')

class ColorScheme:
    folder = "[yellow]"
    task = "[dodger_blue1]"

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(console=console ,omit_repeated_times=False, show_path=False, keywords=[])]
)