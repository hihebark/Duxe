BOLD        = "\033[1m"
DIM         = "\033[2m"
RED         = "\033[31m"
GREEN       = "\033[32m"
BLUE        = "\033[34m"
YELLOW      = "\033[33m"
FG_BLACK    = "\033[30m"
FG_WHITE    = "\033[97m"
BG_DGRAY    = "\033[100m"
BG_RED      = "\033[41m"
BG_GREEN    = "\033[42m"
BG_YELLOW   = "\033[43m"
BG_LBLUE    = "\033[104m"
RESET       = "\033[0m"

def red(string):
    return RED+string+RESET

def redbold(string):
    return RED+BG_RED+string+RESET

def green(string):
    return GREEN+string+RESET

def greenbold(string):
    return RED+BG_GREEN+string+RESET

def blue(string):
    return BLUE+string+RESET

def bluebold(string):
    return BLUE+BG_LBLUE+string+RESET

def yellow(string):
    return YELLOW+string+RESET

def yellowbold(string):
    return YELLOW+BG_YELLOW+string+RESET

