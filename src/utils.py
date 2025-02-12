ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE   = "\u001b[34m"
ANSI_RED    = "\u001b[31m"
ANSI_RESET  = "\u001b[0m"

def warn(*args, **kwargs):
    print(f"{ANSI_YELLOW}[WARN]{ANSI_RESET}", *args, **kwargs)

def info(*args, **kwargs):
    print(f"{ANSI_BLUE}[INFO]{ANSI_RESET}", *args, **kwargs)

def error(*args, **kwargs):
    print(f"{ANSI_RED}[ERROR]{ANSI_RESET}", *args, **kwargs)
