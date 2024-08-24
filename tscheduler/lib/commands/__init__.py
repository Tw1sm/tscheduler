from tscheduler.lib.commands import delete, disable, enable, enum, hijack, register, start, stop

#
# originally started this code base with the focus on the hijack module,
#   looking for a task-based equilvant to service DLL hijacking
#   but it never really panned out (and all the hijacks were system 32 dlls)
#   Commented that module out, but left the code in case someone finds it useful
#
all = [
    register,
    delete,
    disable,
    enable,
    enum,
    #hijack,
    start,
    stop
]