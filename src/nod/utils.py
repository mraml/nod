import re
import sys
import os

class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

def colorize(text: str, color: str) -> str:
    """Apply ANSI color if output is a TTY and NO_COLOR is not set."""
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    return f"{color}{text}{Colors.RESET}" if use_color else text

def clean_header(text: str) -> str:
    """Normalizes regex patterns into readable headers."""
    text = re.sub(r"[#+*?^$\[\](){}|]", "", text).strip()
    text = text.replace(".*", " ").replace(".", " ")
    return " ".join(text.split())

def get_line_number(content: str, index: int) -> int:
    """Calculates line number from character index."""
    return content.count("\n", 0, index) + 1

def resolve_source(content: str, index: int) -> str:
    """Determines source file from aggregated content based on index."""
    best_source = "unknown"
    for match in re.finditer(r"<!-- SOURCE: (.*?) -->", content):
        if match.start() < index:
            best_source = match.group(1)
        else:
            break
    return best_source
