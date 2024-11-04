# tscheduler
Impackt-based utility to remotely manage scheduled tasks over RPC. Task registration/updates take raw XML definitions (examples in the `examples/` folder).

# Installation
```
git clone https://github.com/tw1sm/tscheduler
cd tscheduler
pip3 install .
tscheduler --help
```

# Usage
```
 Usage: tscheduler [OPTIONS] COMMAND [ARGS]...                                                                
                                                                                                              
╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────╮
│ delete     Delete a scheduled task                                                                         │
│ disable    Disable an enabled scheduled task                                                               │
│ enable     Enable a disabled scheduled task                                                                │
│ enum       Enumerate scheduled tasks and/or folders                                                        │
│ register   Register a new scheduled task or update an existing one                                         │
│ start      Execute a scheduled task                                                                        │
│ stop       Stop a runnung scheduled task                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
- The `enum` module can enumerate all tasks, a folder of tasks, or just retrive the XML definition of a single task
- An existing scheudled task can be modified using the `register` module and the `--update` flag

# Development
This project uses Poetry to manage dependencies. Install from source and setup for development with:

```shell
git clone https://github.com/tw1sm/tscheduler
cd tscheduler
poetry install
poetry run tscheduler --help
```
