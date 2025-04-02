ANSI_BRIGHT_GREEN = "\u001b[32;1m"
ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE = "\u001b[34m"
ANSI_RED = "\u001b[31m"
ANSI_RESET = "\u001b[0m"


class Logger:
    def __init__(self):
        pass

    def important(self, msg):
        print(f"{ANSI_BRIGHT_GREEN}[!] {msg}{ANSI_RESET}")

    def warn(self, *args, **kwargs):
        print(f"{ANSI_YELLOW}[*]{ANSI_RESET}", *args, **kwargs)

    def info(self, *args, **kwargs):
        print(f"{ANSI_BLUE}[+]{ANSI_RESET}", *args, **kwargs)

    def error(self, *args, **kwargs):
        print(f"{ANSI_RED}[-]{ANSI_RESET}", *args, **kwargs)
        exit(-1)
